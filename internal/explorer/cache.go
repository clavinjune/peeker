package explorer

import (
	"context"
	"errors"
	"time"
)

const collectionTTL = 20 * time.Second

type collectionRead struct {
	done    chan struct{}
	timer   *time.Timer
	expires time.Time
	value   Collection
}

func (c *Client) Close() {
	c.cancel()
	c.invalidate()
	c.http.CloseIdleConnections()
}

func (c *Client) invalidate() {
	c.cacheMu.Lock()
	for _, entry := range c.cache {
		if entry.timer != nil {
			entry.timer.Stop()
		}
	}
	c.cache = map[string]*collectionRead{}
	c.cacheMu.Unlock()
}

func (c *Client) cachedList(ctx context.Context, r resource, ns string) Collection {
	if !r.namespaced {
		ns = ""
	}
	key := r.key + "/" + ns
	c.cacheMu.Lock()
	for key, entry := range c.cache {
		if !entry.expires.IsZero() && time.Now().After(entry.expires) {
			delete(c.cache, key)
		}
	}
	entry := c.cache[key]
	if entry == nil {
		if len(c.cache) >= 128 || c.pending >= 128 || c.ctx.Err() != nil {
			c.cacheMu.Unlock()
			return failed(r.key, errors.New("Resource cache is busy; retry shortly"), false)
		}
		entry = &collectionRead{done: make(chan struct{})}
		c.pending++
		c.cache[key] = entry
		go c.loadCollection(r, ns, key, entry)
	}
	c.cacheMu.Unlock()
	select {
	case <-ctx.Done():
		return failed(r.key, ctx.Err(), false)
	case <-entry.done:
		return entry.value
	}
}

func (c *Client) loadCollection(r resource, ns, key string, entry *collectionRead) {
	ctx, cancel := context.WithTimeout(c.ctx, 30*time.Second)
	defer cancel()
	select {
	case c.reads <- struct{}{}:
		entry.value = c.list(ctx, r, ns)
		<-c.reads
	case <-ctx.Done():
		entry.value = failed(r.key, ctx.Err(), false)
	}
	entry.value = indexCollection(entry.value, ns)
	c.cacheMu.Lock()
	c.pending--
	entry.expires = time.Now().Add(collectionTTL)
	close(entry.done)
	if c.cache[key] == entry {
		entry.timer = time.AfterFunc(collectionTTL, func() {
			c.cacheMu.Lock()
			defer c.cacheMu.Unlock()
			if c.cache[key] == entry {
				delete(c.cache, key)
			}
		})
	}
	c.cacheMu.Unlock()
}

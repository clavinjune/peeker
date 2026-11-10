import { readFile, writeFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToString } from 'react-dom/server';
import { App } from '../src/App.tsx';

const index = new URL('../dist/index.html', import.meta.url);
const template = await readFile(index, 'utf8');
const placeholder = '<div id="root"></div>';
if (!template.includes(placeholder)) throw new Error('Missing frontend prerender placeholder');
const html = renderToString(createElement(App));
await writeFile(index, template.replace(placeholder, () => `<div id="root">${html}</div>`));
console.log('Prerendered the Peeker application shell to dist/index.html');

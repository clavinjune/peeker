from pathlib import Path
import re


PATTERNS = {
    "private key": r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
    "GitHub credential": r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b",
    "AWS credential ID": r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
    "JWT credential": r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b",
    "kubeconfig credential": r"(?:client-key-data|client-certificate-data|certificate-authority-data):",
    "local filesystem path": r"/(?:Users/|private/(?:tmp|var)/|home/[A-Za-z0-9_-]+/)",
    "source map": r"sourceMappingURL=",
    "development server": r"(?:127\.0\.0\.1|localhost):5173|/src/main\.tsx|/@vite/client",
}


def check_dist(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("dist must be a real directory")
    files = []
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise ValueError(f"symlink is not publishable: {relative}")
        if path.is_dir():
            if relative != "assets":
                raise ValueError(f"unexpected directory: {relative}")
            continue
        if relative != "index.html" and not re.fullmatch(r"assets/[A-Za-z0-9_-]+-[A-Za-z0-9_-]+\.(?:js|css)", relative):
            raise ValueError(f"unexpected generated file: {relative}")
        content = path.read_text(encoding="utf-8")
        for label, pattern in PATTERNS.items():
            if re.search(pattern, content):
                raise ValueError(f"{label} detected in {relative}")
        files.append(relative)
    index = (root / "index.html").read_text(encoding="utf-8")
    if '<div id="root"></div>' in index or "CLUSTER INVENTORY" not in index:
        raise ValueError("index.html must contain the static application shell")
    links = re.findall(r'(?:src|href)="/([^\"]+)"', index)
    if not any(p.endswith(".js") for p in links) or not any(p.endswith(".css") for p in links):
        raise ValueError("index.html must link built JavaScript and CSS")
    if set(links) != set(files) - {"index.html"}:
        raise ValueError("generated assets must exactly match the index links")
    return files


if __name__ == "__main__":
    files = check_dist(Path(__file__).resolve().parents[1] / "web" / "dist")
    print(f"Publication check passed: {len(files)} static files; no detected credentials, local paths, source maps or development entry points")

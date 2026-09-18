import html, re, json, glob, os

rows = []
for path in sorted(glob.glob("gtfobins_pages/*.html")):
    bin_name = os.path.basename(path)[:-5]
    with open(path, encoding="utf-8") as f:
        content = f.read()
    if "<title>Page not found" in content:
        continue
    # bare <pre><code>...</code></pre> blocks (not the inline language-plaintext spans)
    blocks = re.findall(r"<pre><code>(.*?)</code></pre>", content, flags=re.S)
    seen = set()
    for b in blocks:
        # strip any nested tags (rare), unescape entities
        text = re.sub(r"<[^>]+>", "", b)
        text = html.unescape(text).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        rows.append({"command": text, "binary": bin_name})

print(f"binaries with pages: {len(set(r['binary'] for r in rows))}")
print(f"total unique command snippets: {len(rows)}")

with open("sources/gtfobins_extracted.jsonl", "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")

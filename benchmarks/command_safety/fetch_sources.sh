#!/usr/bin/env bash
# Downloads the raw open-source corpora used by build_dataset.py.
# Re-run this before build_dataset.py if sources/ is missing.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p sources gtfobins_pages

# --- GTFOBins (Unix living-off-the-land binaries) ---
# Discover the list of documented binaries from the site index, then fetch each page.
curl -sSL --max-time 20 "https://gtfobins.github.io/" -o /tmp/gtfobins_index.html
grep -oE '/gtfobins/[a-z0-9_.+-]+/' /tmp/gtfobins_index.html | sort -u | sed 's#/gtfobins/##;s#/##' > /tmp/gtfobins_names.txt
xargs -a /tmp/gtfobins_names.txt -P 20 -I{} curl -sSL --max-time 15 -o "gtfobins_pages/{}.html" "https://gtfobins.github.io/gtfobins/{}/"
python3 extract_gtfobins.py

# --- LOLBAS (Windows living-off-the-land binaries) ---
curl -sS --max-time 30 "https://lolbas-project.github.io/api/lolbas.json" -o sources/lolbas.json

# --- nl2bash (benign real-world shell one-liners from Q&A forums) ---
curl -sS --max-time 60 "https://raw.githubusercontent.com/TellinaTool/nl2bash/master/data/bash/all.cm" -o sources/nl2bash_all.cm

echo "Done. Now run: python3 build_dataset.py"

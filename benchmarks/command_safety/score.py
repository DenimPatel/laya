import json
from collections import Counter, defaultdict

rows = [json.loads(l) for l in open("predictions.jsonl")]
errors = [r for r in rows if "error" in r]
rows = [r for r in rows if "error" not in r]
print(f"total={len(rows)} errors={len(errors)}")
if errors:
    print("sample error:", errors[0])

def is_pos(label):
    return label == "malicious"

# --- threshold sweep on p_malicious for malicious vs benign (excluding risky_benign) ---
core = [r for r in rows if r["label"] in ("malicious", "benign")]
print(f"\ncore (malicious+benign) n={len(core)}")

best = None
for t in [i / 100 for i in range(1, 100)]:
    tp = sum(1 for r in core if r["p_malicious"] >= t and r["label"] == "malicious")
    fp = sum(1 for r in core if r["p_malicious"] >= t and r["label"] == "benign")
    fn = sum(1 for r in core if r["p_malicious"] < t and r["label"] == "malicious")
    tn = sum(1 for r in core if r["p_malicious"] < t and r["label"] == "benign")
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    acc = (tp + tn) / len(core)
    if best is None or f1 > best["f1"]:
        best = dict(t=t, tp=tp, fp=fp, fn=fn, tn=tn, prec=prec, rec=rec, f1=f1, acc=acc)

print("\nBest-F1 threshold on p_malicious:")
for k, v in best.items():
    print(f"  {k}: {v}")

# metrics at natural 0.5 threshold
t = 0.5
tp = sum(1 for r in core if r["p_malicious"] >= t and r["label"] == "malicious")
fp = sum(1 for r in core if r["p_malicious"] >= t and r["label"] == "benign")
fn = sum(1 for r in core if r["p_malicious"] < t and r["label"] == "malicious")
tn = sum(1 for r in core if r["p_malicious"] < t and r["label"] == "benign")
prec = tp / (tp + fp) if (tp + fp) else 0
rec = tp / (tp + fn) if (tp + fn) else 0
f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
acc = (tp + tn) / len(core)
print(f"\nAt fixed threshold 0.5: tp={tp} fp={fp} fn={fn} tn={tn} prec={prec:.3f} rec={rec:.3f} f1={f1:.3f} acc={acc:.3f}")

# AUC via rank statistic (Mann-Whitney)
mal_scores = sorted([r["p_malicious"] for r in core if r["label"] == "malicious"])
ben_scores = sorted([r["p_malicious"] for r in core if r["label"] == "benign"])
all_scores = sorted(core, key=lambda r: r["p_malicious"])
ranks = {}
i = 0
n = len(all_scores)
vals = [r["p_malicious"] for r in all_scores]
while i < n:
    j = i
    while j < n and vals[j] == vals[i]:
        j += 1
    avg_rank = (i + 1 + j) / 2.0
    for k in range(i, j):
        ranks[k] = avg_rank
    i = j
sum_rank_pos = sum(ranks[k] for k, r in enumerate(all_scores) if r["label"] == "malicious")
n_pos = len(mal_scores)
n_neg = len(ben_scores)
auc = (sum_rank_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)
print(f"\nAUC-ROC (malicious vs benign): {auc:.4f}")

# breakdown by source within malicious
print("\nMean p_malicious by source (ground-truth malicious commands):")
by_src = defaultdict(list)
for r in rows:
    if r["label"] == "malicious":
        by_src[r["source"]].append(r["p_malicious"])
for src, vals in by_src.items():
    print(f"  {src}: n={len(vals)} mean={sum(vals)/len(vals):.3f} >=0.5 rate={sum(1 for v in vals if v>=0.5)/len(vals):.3f}")

print("\nMean p_malicious for benign (nl2bash):",
      sum(r["p_malicious"] for r in rows if r["label"]=="benign")/sum(1 for r in rows if r["label"]=="benign"))

# risky_benign (gray zone) behavior
gray = [r for r in rows if r["label"] == "risky_benign"]
print(f"\nGray-zone risky-but-legitimate commands (n={len(gray)}):")
print("  mean p_malicious:", sum(r["p_malicious"] for r in gray) / len(gray))
print("  action distribution:", Counter(r["suggested_action"] for r in gray))
print("  fraction with p_malicious >= 0.5:", sum(1 for r in gray if r["p_malicious"] >= 0.5) / len(gray))
print("  worst false-alarms (highest p_malicious):")
for r in sorted(gray, key=lambda r: -r["p_malicious"])[:8]:
    print(f"    p={r['p_malicious']:.3f} action={r['suggested_action']:15s} cmd={r['command']}")

# suggested_action distribution vs label
print("\nsuggested_action distribution by true label:")
for label in ("malicious", "benign", "risky_benign"):
    subset = [r for r in rows if r["label"] == label]
    print(f"  {label}: {dict(Counter(r['suggested_action'] for r in subset))}")

# worst false negatives (malicious scored very low)
print("\nWorst false negatives (malicious commands laya scored as safe):")
fns = sorted([r for r in core if r["label"] == "malicious"], key=lambda r: r["p_malicious"])[:10]
for r in fns:
    print(f"  p={r['p_malicious']:.3f} src={r['source']:10s} cmd={r['command'][:90]}")

# worst false positives (benign commands laya scored as very risky)
print("\nWorst false positives (benign commands laya scored as risky):")
fps = sorted([r for r in core if r["label"] == "benign"], key=lambda r: -r["p_malicious"])[:10]
for r in fps:
    print(f"  p={r['p_malicious']:.3f} cmd={r['command'][:90]}")

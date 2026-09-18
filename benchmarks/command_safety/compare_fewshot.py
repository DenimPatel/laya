import json
from collections import Counter, defaultdict

base = {json.loads(l)["id"]: json.loads(l) for l in open("predictions.jsonl") if "error" not in json.loads(l)}
few = {json.loads(l)["id"]: json.loads(l) for l in open("predictions_fewshot.jsonl") if "error" not in json.loads(l)}

def metrics(preds, label_filter=("malicious", "benign")):
    core = [r for r in preds.values() if r["label"] in label_filter]
    best = None
    for i in range(1, 100):
        t = i / 100
        tp = sum(1 for r in core if r["p_malicious"] >= t and r["label"] == "malicious")
        fp = sum(1 for r in core if r["p_malicious"] >= t and r["label"] == "benign")
        fn = sum(1 for r in core if r["p_malicious"] < t and r["label"] == "malicious")
        tn = sum(1 for r in core if r["p_malicious"] < t and r["label"] == "benign")
        prec = tp / (tp + fp) if (tp + fp) else 0
        rec = tp / (tp + fn) if (tp + fn) else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
        if best is None or f1 > best["f1"]:
            best = dict(t=t, prec=prec, rec=rec, f1=f1, acc=(tp + tn) / len(core))
    # AUC
    mal = [r["p_malicious"] for r in core if r["label"] == "malicious"]
    ben = [r["p_malicious"] for r in core if r["label"] == "benign"]
    allr = sorted(core, key=lambda r: r["p_malicious"])
    vals = [r["p_malicious"] for r in allr]
    ranks = {}
    i = 0
    n = len(allr)
    while i < n:
        j = i
        while j < n and vals[j] == vals[i]:
            j += 1
        avg = (i + 1 + j) / 2.0
        for k in range(i, j):
            ranks[k] = avg
        i = j
    sum_rank_pos = sum(ranks[k] for k, r in enumerate(allr) if r["label"] == "malicious")
    auc = (sum_rank_pos - len(mal) * (len(mal) + 1) / 2) / (len(mal) * len(ben))
    return best, auc

print("=== Overall (malicious vs benign) ===")
b_best, b_auc = metrics(base)
f_best, f_auc = metrics(few)
print(f"baseline : AUC={b_auc:.4f}  best-F1 t={b_best['t']:.2f} prec={b_best['prec']:.3f} rec={b_best['rec']:.3f} f1={b_best['f1']:.3f} acc={b_best['acc']:.3f}")
print(f"few-shot : AUC={f_auc:.4f}  best-F1 t={f_best['t']:.2f} prec={f_best['prec']:.3f} rec={f_best['rec']:.3f} f1={f_best['f1']:.3f} acc={f_best['acc']:.3f}")

# find-benign specific (the dominant FP theme)
def find_subset(preds, pred_fn):
    return {i: r for i, r in preds.items() if r["label"] == "benign" and pred_fn(r["command"])}

is_find = lambda c: c.split()[0] == "find"
base_find = find_subset(base, is_find)
few_find = find_subset(few, is_find)
b_mean = sum(r["p_malicious"] for r in base_find.values()) / len(base_find)
f_mean = sum(r["p_malicious"] for r in few_find.values()) / len(few_find)
b_flagged = sum(1 for r in base_find.values() if r["p_malicious"] >= 0.5) / len(base_find)
f_flagged = sum(1 for r in few_find.values() if r["p_malicious"] >= 0.5) / len(few_find)
print(f"\n=== 'find'-prefixed benign commands (n={len(base_find)}) ===")
print(f"baseline : mean p_malicious={b_mean:.3f}  flagged>=0.5={b_flagged:.3f}")
print(f"few-shot : mean p_malicious={f_mean:.3f}  flagged>=0.5={f_flagged:.3f}")

# bare/short malicious commands (<=2 words) -- the dominant FN theme
def word_count(c):
    return len(c.split())
base_short_mal = {i: r for i, r in base.items() if r["label"] == "malicious" and word_count(r["command"]) <= 2}
few_short_mal = {i: r for i, r in few.items() if r["label"] == "malicious" and word_count(r["command"]) <= 2}
b_mean2 = sum(r["p_malicious"] for r in base_short_mal.values()) / len(base_short_mal)
f_mean2 = sum(r["p_malicious"] for r in few_short_mal.values()) / len(few_short_mal)
b_caught = sum(1 for r in base_short_mal.values() if r["p_malicious"] >= 0.5) / len(base_short_mal)
f_caught = sum(1 for r in few_short_mal.values() if r["p_malicious"] >= 0.5) / len(few_short_mal)
print(f"\n=== Short/bare malicious commands (<=2 words, n={len(base_short_mal)}) ===")
print(f"baseline : mean p_malicious={b_mean2:.3f}  caught>=0.5={b_caught:.3f}")
print(f"few-shot : mean p_malicious={f_mean2:.3f}  caught>=0.5={f_caught:.3f}")

# net flip counts on the core set at threshold 0.5
core_ids = [i for i, r in base.items() if r["label"] in ("malicious", "benign")]
flips_fixed = 0   # was wrong, now right
flips_broken = 0  # was right, now wrong
for i in core_ids:
    b, fw = base[i], few[i]
    b_correct = (b["p_malicious"] >= 0.5) == (b["label"] == "malicious")
    f_correct = (fw["p_malicious"] >= 0.5) == (fw["label"] == "malicious")
    if not b_correct and f_correct:
        flips_fixed += 1
    elif b_correct and not f_correct:
        flips_broken += 1
print(f"\n=== Net effect at fixed threshold 0.5 ===")
print(f"fixed by few-shot: {flips_fixed}   broken by few-shot: {flips_broken}   net: {flips_fixed - flips_broken}")

# gray zone
base_gray = {i: r for i, r in base.items() if r["label"] == "risky_benign"}
few_gray = {i: r for i, r in few.items() if r["label"] == "risky_benign"}
b_mean3 = sum(r["p_malicious"] for r in base_gray.values()) / len(base_gray)
f_mean3 = sum(r["p_malicious"] for r in few_gray.values()) / len(few_gray)
print(f"\n=== Gray zone (risky-but-legitimate, n={len(base_gray)}) ===")
print(f"baseline : mean p_malicious={b_mean3:.3f}")
print(f"few-shot : mean p_malicious={f_mean3:.3f}")

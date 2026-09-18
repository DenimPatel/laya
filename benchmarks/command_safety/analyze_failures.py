import json, re
from collections import Counter

rows = [json.loads(l) for l in open("predictions.jsonl") if "error" not in json.loads(l)]

fn = [r for r in rows if r["label"] == "malicious" and r["p_malicious"] < 0.5]
fp = [r for r in rows if r["label"] == "benign" and r["p_malicious"] >= 0.5]

print(f"False negatives (malicious scored safe): {len(fn)} / {sum(1 for r in rows if r['label']=='malicious')}")
print(f"False positives (benign scored risky):   {len(fp)} / {sum(1 for r in rows if r['label']=='benign')}")

def word_count(cmd):
    return len(cmd.split())

print("\n--- FN: word-count distribution (short commands = missing context) ---")
buckets = Counter()
for r in fn:
    n = word_count(r["command"])
    b = "1-2" if n <= 2 else "3-5" if n <= 5 else "6-10" if n <= 10 else "11+"
    buckets[b] += 1
print(buckets)
print(f"  fraction of FN with <=2 words: {sum(1 for r in fn if word_count(r['command'])<=2)/len(fn):.2f}")

print("\n--- FN: does command contain a help/no-op subcommand? ---")
help_like = re.compile(r"\b(help|--help|-h|--version|-v)\b")
n_help = sum(1 for r in fn if help_like.search(r["command"]))
print(f"  {n_help}/{len(fn)} FN contain help/version-like tokens")

print("\n--- FN: bare binary name with no args at all ---")
bare = [r for r in fn if word_count(r["command"]) == 1]
print(f"  {len(bare)}/{len(fn)} are a single bare token")
for r in bare[:15]:
    print("   ", r["command"])

print("\n--- FP: does command contain pipe/exec/xargs (attack-shaped-but-safe) ---")
shape = re.compile(r"(\|)|(-exec\b)|(\bxargs\b)|(\btmux\b)|(\bssh\b)")
n_shape = sum(1 for r in fp if shape.search(r["command"]))
print(f"  {n_shape}/{len(fp)} FP contain pipe/exec/xargs/tmux/ssh")

print("\n--- FP: command length (chars) distribution vs overall benign ---")
import statistics
fp_lens = [len(r["command"]) for r in fp]
all_benign_lens = [len(r["command"]) for r in rows if r["label"] == "benign"]
print(f"  FP mean len: {statistics.mean(fp_lens):.1f}  median: {statistics.median(fp_lens):.1f}")
print(f"  all benign mean len: {statistics.mean(all_benign_lens):.1f}  median: {statistics.median(all_benign_lens):.1f}")

print("\n--- FP: most common first tokens ---")
first_tok = Counter(r["command"].split()[0] for r in fp if r["command"].split())
print(first_tok.most_common(15))

print("\n--- FN: most common binaries (GTFOBins 'binary' detail not in predictions; approx by first token) ---")
first_tok_fn = Counter(r["command"].split()[0] for r in fn if r["command"].split())
print(first_tok_fn.most_common(20))

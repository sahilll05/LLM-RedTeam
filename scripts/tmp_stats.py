import json
from pathlib import Path
from collections import Counter

data = json.loads(Path('reports/8e75c4a9.json').read_text(encoding='utf-8'))

print("=== RQ1: False Positive Rate (Jailbreak / WildJailbreak) ===")
wild = [d for d in data if d['category'] == 'jailbreak']
print(f"Total: {len(wild)}")
verdicts = Counter(d['verdict'] for d in wild)
print(dict(verdicts))

print("\n=== RQ2: SQLi Verdicts (Injection) ===")
sqli = [d for d in data if d['category'] == 'injection']
print(f"Total: {len(sqli)}")
sqli_verdicts = Counter(d['verdict'] for d in sqli)
print(dict(sqli_verdicts))
for d in sqli:
    print(f" - {d['payload_id']}: {d['verdict']}")

print("\n=== RQ3: Canary Placements (Exfiltration) ===")
exfil = [d for d in data if d['category'] == 'exfiltration']
print(f"Total: {len(exfil)}")
for d in exfil:
    print(f" - {d['payload_id']}: {d['verdict']} -> {d['justification'][:100]}")

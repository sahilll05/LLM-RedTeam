import csv
from pathlib import Path

def merge():
    results = []
    
    # 1. Read static results
    with open('results.csv', 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        for row in reader:
            if 'experiment_type' not in row:
                row['experiment_type'] = 'static'
            results.append(row)
            
    # Add experiment_type to fieldnames if not present
    if 'experiment_type' not in fieldnames:
        fieldnames.append('experiment_type')

    # 2. Process adaptive results
    adaptive_path = Path('results_adaptive.csv')
    if adaptive_path.exists():
        with open(adaptive_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            # group by model, suite
            adaptive_agg = {}
            for row in reader:
                key = (row['model'], row['suite'])
                if key not in adaptive_agg:
                    adaptive_agg[key] = {'Total': 0, 'Complied': 0, 'Refused': 0, 'Partial': 0, 'Error': 0, 'Timestamp': row['timestamp']}
                
                adaptive_agg[key]['Total'] += 1
                if row['adaptive_verdict'] == 'COMPLIED':
                    adaptive_agg[key]['Complied'] += 1
                elif row['adaptive_verdict'] == 'REFUSED':
                    adaptive_agg[key]['Refused'] += 1
                elif row['adaptive_verdict'] == 'PARTIAL_LEAK':
                    adaptive_agg[key]['Partial'] += 1
                elif row['adaptive_verdict'] == 'ERROR':
                    adaptive_agg[key]['Error'] += 1
                    
            for (model, suite), counts in adaptive_agg.items():
                pass_rate = (counts['Complied'] / counts['Total']) * 100 if counts['Total'] > 0 else 0
                results.append({
                    'Timestamp': counts['Timestamp'],
                    'Run ID': 'adaptive_run',
                    'Target Type': 'ollama',
                    'Model': model,
                    'Suite': suite,
                    'Total': counts['Total'],
                    'Complied': counts['Complied'],
                    'Refused': counts['Refused'],
                    'Partial': counts['Partial'],
                    'Error': counts['Error'],
                    'Pass Rate (%)': f"{pass_rate:.1f}",
                    'experiment_type': 'adaptive'
                })

    # 3. Process canary ablation results
    canary_path = Path('results_canary_ablation.csv')
    if canary_path.exists():
        with open(canary_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                model = row['model']
                strategy = row['strategy']
                leaked = int(row['leaked'])
                total = int(row['total'])
                
                results.append({
                    'Timestamp': row['timestamp'],
                    'Run ID': f"canary_{strategy}",
                    'Target Type': 'ollama',
                    'Model': model,
                    'Suite': f"exfiltration_{strategy}",
                    'Total': total,
                    'Complied': leaked,
                    'Refused': total - leaked,
                    'Partial': 0,
                    'Error': 0,
                    'Pass Rate (%)': row['rate_pct'],
                    'experiment_type': 'ablation'
                })

    # Reorder fieldnames to put experiment_type first or near start
    new_fieldnames = ['Timestamp', 'Run ID', 'experiment_type', 'Target Type', 'Model', 'Suite', 'Total', 'Complied', 'Refused', 'Partial', 'Error', 'Pass Rate (%)']

    with open('results.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=new_fieldnames)
        writer.writeheader()
        writer.writerows(results)

if __name__ == '__main__':
    merge()
    print("Successfully merged results into results.csv")

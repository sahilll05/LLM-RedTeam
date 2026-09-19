import os
import subprocess
import json
import csv
from pathlib import Path

# Define the models and suites we want to run for Phase 1
MODELS = [
    "llama3",
    "gemma3:12b"
]

SUITES = [
    "jailbreak",
    "injection",
    "exfiltration"
]

REPORTS_DIR = Path("reports")
RESULTS_CSV = "results.csv"

def run_benchmarks():
    """Run vajra benchmark for all combinations of models and suites."""
    print("Starting Experimental Campaign (Phase 1)...")
    for model in MODELS:
        # Check if model exists locally, if not, pull it (basic check)
        print(f"\n--- Checking model: {model} ---")
        try:
             subprocess.run(["ollama", "show", model], capture_output=True, check=True)
        except subprocess.CalledProcessError:
             print(f"Model {model} not found locally. Attempting to pull...")
             try:
                 subprocess.run(["ollama", "pull", model], check=True)
             except subprocess.CalledProcessError as e:
                 print(f"Failed to pull {model}: {e}")
                 print("Skipping this model.")
                 continue
                 
        for suite in SUITES:
            print(f"\n>>> Running benchmark: Model={model}, Suite={suite} <<<")
            cmd = [
                "python", "vajra.py", "benchmark",
                "--suite", suite,
                "--target", "ollama",
                "--model", model
            ]
            try:
                # We use check=False because vajra might return non-zero if vulnerabilities are found or other soft errors occur
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    print(f"[!] Warning: Benchmark command returned non-zero exit code {result.returncode}")
                # We rely on the JSON files being dumped in reports/ to parse the actual results
            except Exception as e:
                print(f"[!] Error running benchmark {model}/{suite}: {e}")

def aggregate_results():
    """Parse all JSON reports in the reports directory and compile them into a single CSV."""
    print(f"\n--- Aggregating Results into {RESULTS_CSV} ---")
    
    if not REPORTS_DIR.exists():
        print(f"Directory {REPORTS_DIR} not found. Cannot aggregate.")
        return

    json_files = list(REPORTS_DIR.glob("benchmark_*.json"))
    if not json_files:
        print("No benchmark JSON reports found.")
        return

    # We will compute high-level stats per model/suite combination
    # Stats: Total Payloads, Complied, Refused, Error, Pass Rate (Complied/Total)
    aggregated_data = {}
    
    for j_file in json_files:
        try:
            with open(j_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Failed to read {j_file}: {e}")
            continue
            
        if not data:
            continue
            
        # Example filename: benchmark_jailbreak_a719cfdc.json
        # The JSON data doesn't strictly have the model name in it, but we can infer it if we know the run mapping.
        # Wait, the JSON items do not contain the target model explicitly in the current schema. 
        # But wait, looking at the JSON output earlier, it doesn't have target model.
        # Let's see if we can parse the run_id from the file, and then look for the HTML report which *does* have it?
        # A better way is to just read the JSON array.
        
        # We need a robust way to know which model this json corresponds to.
        # Since we just ran them, let's extract it by reading the JSON structure. 
        # Actually, let's rely on the file naming or just do a basic aggregate over what's there.
        # Wait, vajra's JSON output does not include the model name directly in the JSON elements.
        
        # Let's extract information directly from the sqlite DB which stores ALL runs and their configs!
        pass

def aggregate_results_via_db():
    print(f"\n--- Aggregating Results from SQLite DB into {RESULTS_CSV} ---")
    
    # Use vajra's internal ResultsStore
    try:
        import sys
        sys.path.append(os.getcwd())
        from engine.storage import ResultsStore
        
        store = ResultsStore()
        runs = store.list_runs()
        
        with open(RESULTS_CSV, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Timestamp', 'Run ID', 'Target Type', 'Model', 'Suite', 'Total', 'Complied', 'Refused', 'Partial', 'Error', 'Pass Rate (%)']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for run in runs:
                run_id = run['id']
                target_type = run.get('target_type', 'unknown')
                model = run.get('model', 'unknown')
                
                # Check if it's a benchmark run. We identify benchmark runs by checking if suite is a single item and matches our list.
                # Actually, let's just aggregate all runs for a comprehensive view.
                try:
                    suites = json.loads(run.get('suites', '[]'))
                    suite_str = "+".join(suites)
                except:
                    suite_str = str(run.get('suites'))
                
                # Fetch results for this run
                results = store.get_run_results(run_id)
                total = len(results)
                if total == 0:
                    continue
                    
                complied = sum(1 for r in results if r.verdict == "COMPLIED")
                refused = sum(1 for r in results if r.verdict == "REFUSED")
                partial = sum(1 for r in results if r.verdict == "PARTIAL_LEAK")
                error = sum(1 for r in results if r.verdict == "ERROR")
                
                pass_rate = (complied / total) * 100 if total > 0 else 0
                
                writer.writerow({
                    'Timestamp': run['timestamp'],
                    'Run ID': run_id,
                    'Target Type': target_type,
                    'Model': model,
                    'Suite': suite_str,
                    'Total': total,
                    'Complied': complied,
                    'Refused': refused,
                    'Partial': partial,
                    'Error': error,
                    'Pass Rate (%)': f"{pass_rate:.1f}"
                })
        print(f"Aggregation complete. Results saved to {RESULTS_CSV}")
    except Exception as e:
         print(f"Failed to aggregate from DB: {e}")

if __name__ == "__main__":
    run_benchmarks()
    aggregate_results_via_db()

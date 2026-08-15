import os
import argparse
import json
import signal
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def write_failure_marker(path, metadata):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump(metadata, f, indent=4)

def process_file(args):
    (
        input_path,
        output_path,
        result_json,
        failure_json,
        log_path,
        c_budget,
        detector,
        timeout,
        keep_success_logs,
    ) = args
    cmd = [
        "python3", "pipeline/run_malguise.py",
        "--input", input_path,
        "--output", output_path,
        "--c-budget", str(c_budget),
        "--max-length", str(max_length),
        "--time-budget", str(max(1, timeout - 120)),
        "--detector", detector
    ]
    start_time = time.time()
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)

    with open(log_path, "w") as log_file:
        log_file.write(f"Command: {' '.join(cmd)}\n")
        log_file.write(f"Input: {input_path}\n")
        log_file.write(f"Output: {output_path}\n")
        log_file.write(f"Timeout: {timeout}s\n")
        log_file.write("=" * 80 + "\n")
        log_file.flush()

        proc = subprocess.Popen(
            cmd,
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )

        try:
            returncode = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

            try:
                returncode = proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                returncode = proc.wait()

            duration = time.time() - start_time
            log_file.write("\n" + "=" * 80 + "\n")
            log_file.write(f"TIMEOUT after {duration:.1f}s; returncode={returncode}\n")
            write_failure_marker(failure_json, {
                "sample_id": Path(input_path).stem,
                "input_path": input_path,
                "output_path": output_path,
                "success": False,
                "status": "timeout",
                "returncode": returncode,
                "duration_seconds": duration,
                "timeout_seconds": timeout,
                "log_path": log_path,
                "command": cmd,
            })
            return (input_path, False, f"Timeout ({timeout}s)", log_path)

    duration = time.time() - start_time

    try:
        if returncode == 0 and os.path.exists(result_json):
            with open(result_json, "r") as f:
                metadata = json.load(f)
            evaded = bool(metadata.get("success", False))
            status = metadata.get("status", "evaded" if evaded else "best_effort_not_evaded")
            final_probability = metadata.get("final_probability")

            if os.path.exists(failure_json):
                os.remove(failure_json)

            if not keep_success_logs and evaded and os.path.exists(log_path):
                os.remove(log_path)

            if evaded:
                return (input_path, True, f"Success ({duration:.1f}s, prob={final_probability})", None)

            return (
                input_path,
                False,
                f"Best Effort Saved ({status}, prob={final_probability})",
                log_path,
            )
        else:
            log_tail = ""
            try:
                with open(log_path, "r", errors="replace") as f:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 16000))
                    log_tail = f.read()
            except OSError:
                pass

            if "[FAILURE]" in log_tail:
                status = "evasion_failed"
                msg = "Evasion Failed"
            else:
                status = "runtime_error"
                msg = f"Error (Exit Code {returncode})"

            write_failure_marker(failure_json, {
                "sample_id": Path(input_path).stem,
                "input_path": input_path,
                "output_path": output_path,
                "success": False,
                "status": status,
                "returncode": returncode,
                "duration_seconds": duration,
                "timeout_seconds": timeout,
                "log_path": log_path,
                "command": cmd,
            })
            return (input_path, False, msg, log_path)
    except Exception as e:
        return (input_path, False, str(e), log_path)

def main():
    parser = argparse.ArgumentParser(description="Batch Evaluate MalGuise")
    parser.add_argument("--data-dir", type=str, default="data/Test", help="Directory containing test malware families")
    parser.add_argument("--results-dir", type=str, default="results", help="Directory to save adversarial malware")
    parser.add_argument("--c-budget", type=int, default=40, help="MCTS Compute Budget")
    parser.add_argument("--max-length", type=int, default=6, help="Maximum transformation length")
    parser.add_argument("--detector", type=str, default="magic", help="Target detector")
    parser.add_argument("--workers", type=int, default=24, help="Number of concurrent workers (threads/processes)")
    parser.add_argument("--timeout", type=int, default=1800, help="Per-sample timeout in seconds")
    parser.add_argument("--resume", action="store_true", help="Skip samples that already have a result JSON")
    parser.add_argument("--retry-failed", action="store_true", help="Retry samples with an existing failure marker")
    parser.add_argument("--retry-best-effort", action="store_true", help="Retry samples that saved a best-effort non-evading result")
    parser.add_argument("--keep-success-logs", action="store_true", help="Keep per-sample logs even for successful samples")
    args = parser.parse_args()

    files = []
    for root, _, filenames in os.walk(args.data_dir):
        for f in filenames:
            if f.endswith(".exe"):
                files.append(os.path.join(root, f))
    files.sort()
    
    logging.info(f"Found {len(files)} files to process in {args.data_dir}")
    
    tasks = []
    data_dir = Path(args.data_dir).resolve()
    for f in files:
        input_path = Path(f)
        sample_id = input_path.stem
        try:
            rel_path = input_path.resolve().relative_to(data_dir)
            family = rel_path.parts[0] if len(rel_path.parts) > 1 else "unknown_family"
        except ValueError:
            family = input_path.parent.name

        output_path = os.path.join(args.results_dir, family, sample_id, f"{sample_id}_adv.exe")
        result_json = os.path.join(args.results_dir, family, sample_id, f"{sample_id}_adv_result.json")
        failure_json = os.path.join(args.results_dir, family, sample_id, f"{sample_id}_adv_failure.json")
        log_path = os.path.join(args.results_dir, "_logs", family, f"{sample_id}.log")
        
        if args.resume and os.path.exists(result_json):
            if not args.retry_best_effort:
                continue
            try:
                with open(result_json, "r") as f_json:
                    existing_metadata = json.load(f_json)
                if existing_metadata.get("success", False):
                    continue
            except (OSError, json.JSONDecodeError):
                continue

        if args.resume and os.path.exists(failure_json) and not args.retry_failed:
            continue
            
        tasks.append((
            f,
            output_path,
            result_json,
            failure_json,
            log_path,
            args.c_budget,
            args.max_length,
            args.detector,
            args.timeout,
            args.keep_success_logs,
        ))

    if not tasks:
        logging.info("No tasks to run! (All files may have been skipped via --resume)")
        return

    logging.info(f"Starting execution for {len(tasks)} tasks with {args.workers} workers...")
    
    success_count = 0
    failure_count = 0
    
    with ProcessPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(process_file, task): task for task in tasks}
        
        for idx, future in enumerate(as_completed(futures), 1):
            input_path = futures[future][0]
            try:
                _, is_success, msg, log_path = future.result()
                if is_success:
                    success_count += 1
                    logging.info(f"[{idx}/{len(tasks)}] [SUCCESS] {input_path}")
                else:
                    failure_count += 1
                    logging.warning(f"[{idx}/{len(tasks)}] [FAILED] {input_path} - {msg} | log={log_path}")
            except Exception as exc:
                failure_count += 1
                logging.error(f"[{idx}/{len(tasks)}] [ERROR] {input_path} generated an exception: {exc}")
                
    logging.info("========================================")
    logging.info(f"Batch Execution Completed!")
    logging.info(f"Total processed: {len(tasks)} | Success (Evaded): {success_count} | Failed: {failure_count}")

if __name__ == '__main__':
    main()

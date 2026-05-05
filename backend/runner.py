import subprocess
import os
from datetime import datetime
from backend.db import insert_tool_run, update_tool_run, insert_audit_log

def run_tool(scan_id, tool, command, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    output_file = os.path.join(output_dir, f"{tool}_raw.txt")

    print(f"[*] Running {tool}...")
    print(f"[*] Command: {command}")

    run_id = insert_tool_run(scan_id, tool, command)
    insert_audit_log(scan_id, 'tool_started', f"{tool} started at {datetime.now().isoformat()}")

    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )

        with open(output_file, 'w') as f:
            f.write(result.stdout)
            if result.stderr:
                f.write("\n--- STDERR ---\n")
                f.write(result.stderr)

        status = 'completed' if result.returncode == 0 else 'failed'
        update_tool_run(run_id, status, result.returncode, output_file)
        insert_audit_log(scan_id, 'tool_finished', f"{tool} finished with exit code {result.returncode}")

        print(f"[+] {tool} finished — status: {status}")
        return {
            'tool': tool,
            'status': status,
            'output_file': output_file,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_code': result.returncode
        }

    except subprocess.TimeoutExpired:
        update_tool_run(run_id, 'timeout', -1, output_file)
        insert_audit_log(scan_id, 'tool_timeout', f"{tool} timed out")
        print(f"[-] {tool} timed out")
        return {
            'tool': tool,
            'status': 'timeout',
            'output_file': output_file,
            'stdout': '',
            'stderr': 'Tool timed out',
            'exit_code': -1
        }

    except Exception as e:
        update_tool_run(run_id, 'error', -1, output_file)
        insert_audit_log(scan_id, 'tool_error', f"{tool} error: {str(e)}")
        print(f"[-] {tool} error: {str(e)}")
        return {
            'tool': tool,
            'status': 'error',
            'output_file': output_file,
            'stdout': '',
            'stderr': str(e),
            'exit_code': -1
        }

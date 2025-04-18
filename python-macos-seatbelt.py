""" This code was converted to Python by Gemini 2.5 pro from:
https://github.com/openai/codex/blob/0d6a98f9afa8697e57b9bae1095862ebaeb8ffa2/codex-cli/src/utils/agent/sandbox/macos-seatbelt.ts

Then manually cleaned and tested by Donovan Preston.

(c) 2025 Donovan Preston

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


import os
import subprocess
import logging
import shlex
from typing import Dict, Any, Optional, NamedTuple


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s')


class ExecResult(NamedTuple):
    """Holds the result of a subprocess execution."""
    returncode: int
    stdout: str
    stderr: str


READ_ONLY_SEATBELT_POLICY = """
(version 1)

; inspired by Chrome's sandbox policy:
; https://source.chromium.org/chromium/chromium/src/+/main:sandbox/policy/mac/common.sb;l=273-319;drc=7b3962fe2e5fc9e2ee58000dc8fbf3429d84d3bd

; start with closed-by-default
(deny default)

; allow read-only file operations
(allow file-read*)

; child processes inherit the policy of their parent
(allow process-exec)
(allow process-fork)
(allow signal (target self))

(allow file-write-data
  (require-all
    (path "/dev/null")
    (vnode-type CHARACTER-DEVICE)))

; sysctls permitted.
(allow sysctl-read
  (sysctl-name "hw.activecpu")
  (sysctl-name "hw.busfrequency_compat")
  (sysctl-name "hw.byteorder")
  (sysctl-name "hw.cacheconfig")
  (sysctl-name "hw.cachelinesize_compat")
  (sysctl-name "hw.cpufamily")
  (sysctl-name "hw.cpufrequency_compat")
  (sysctl-name "hw.cputype")
  (sysctl-name "hw.l1dcachesize_compat")
  (sysctl-name "hw.l1icachesize_compat")
  (sysctl-name "hw.l2cachesize_compat")
  (sysctl-name "hw.l3cachesize_compat")
  (sysctl-name "hw.logicalcpu_max")
  (sysctl-name "hw.machine")
  (sysctl-name "hw.ncpu")
  (sysctl-name "hw.nperflevels")
  (sysctl-name "hw.optional.arm.FEAT_BF16")
  (sysctl-name "hw.optional.arm.FEAT_DotProd")
  (sysctl-name "hw.optional.arm.FEAT_FCMA")
  (sysctl-name "hw.optional.arm.FEAT_FHM")
  (sysctl-name "hw.optional.arm.FEAT_FP16")
  (sysctl-name "hw.optional.arm.FEAT_I8MM")
  (sysctl-name "hw.optional.arm.FEAT_JSCVT")
  (sysctl-name "hw.optional.arm.FEAT_LSE")
  (sysctl-name "hw.optional.arm.FEAT_RDM")
  (sysctl-name "hw.optional.arm.FEAT_SHA512")
  (sysctl-name "hw.optional.armv8_2_sha512")
  (sysctl-name "hw.memsize")
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.packages")
  (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.physicalcpu_max")
  (sysctl-name "hw.tbfrequency_compat")
  (sysctl-name "hw.vectorunit")
  (sysctl-name "kern.hostname")
  (sysctl-name "kern.maxfilesperproc")
  (sysctl-name "kern.osproductversion")
  (sysctl-name "kern.osrelease")
  (sysctl-name "kern.ostype")
  (sysctl-name "kern.osvariant_status")
  (sysctl-name "kern.osversion")
  (sysctl-name "kern.secure_kernel")
  (sysctl-name "kern.usrstack64")
  (sysctl-name "kern.version")
  (sysctl-name "sysctl.proc_cputype")
  (sysctl-name-prefix "hw.perflevel")
)
""".strip()




def exec_with_seatbelt(
    cmd: list[str],
    opts: Optional[Dict[str, Any]] = None,
    writable_roots: Optional[list[str]] = None,
) -> ExecResult:
  """
  Executes a command within a macOS sandbox-exec environment using subprocess.run,
  optionally allowing writes to specified directories.

  Args:
    cmd: The command and arguments to execute as a list of strings.
    opts: Optional dictionary of options for subprocess.run (e.g., 'cwd', 'env', 'timeout').
    writable_roots: An optional list of directory paths to allow writing to.

  Returns:
    An ExecResult object containing the return code, stdout, and stderr.
  """
  if opts is None:
      opts = {}
  if writable_roots is None:
      writable_roots = []

  scoped_write_policy = ""
  policy_template_params: list[str] = []
  current_writable_roots = list(writable_roots)

  if current_writable_roots:
    # Remove duplicates
    current_writable_roots = list(dict.fromkeys(current_writable_roots))

    policies = []
    params = []
    for index, root in enumerate(current_writable_roots):
      try:
        # Ensure the root exists before getting realpath
        if not os.path.exists(root):
            logging.warning(f"Writable root path '{root}' does not exist. Skipping.")
            continue
        # The kernel resolves symlinks, so use the canonical path.
        real_root = os.path.realpath(root)
        policy_var_name = f"WRITABLE_ROOT_{index}"
        policies.append(f'(subpath (param "{policy_var_name}"))')
        params.append(f"-D{policy_var_name}={real_root}")
      except OSError as e:
        logging.warning(f"Could not get real path for '{root}': {e}. Skipping.")

    if policies:
      policy_lines = "\n".join(f"  {p}" for p in policies)
      scoped_write_policy = f"\n(allow file-write*\n{policy_lines}\n)"
      policy_template_params = params
    else:
      scoped_write_policy = ""
      policy_template_params = []
  else:
    scoped_write_policy = ""
    policy_template_params = []

  full_policy = READ_ONLY_SEATBELT_POLICY + scoped_write_policy

  logging.info(
      f"Running seatbelt with {len(policy_template_params)} template params"
  )
  logging.debug(f"Full sandbox policy:\n{full_policy}") # Log policy on debug level

  full_command = [
      "sandbox-exec",
      "-p",
      full_policy,
      *policy_template_params,
      "--",
      *cmd,
  ]

  subprocess_opts = {
      "capture_output": True,
      "text": True,
      "check": False,
  }
  for key in ["cwd", "env", "timeout"]:
      if key in opts:
          subprocess_opts[key] = opts[key]

  try:
      logging.debug(f"Executing command: {' '.join(shlex.quote(str(s)) for s in full_command)}")
      # Execute using subprocess.run
      completed_process = subprocess.run(full_command, **subprocess_opts)

      return ExecResult(
          returncode=completed_process.returncode,
          stdout=completed_process.stdout,
          stderr=completed_process.stderr
      )
  except FileNotFoundError:
      err_msg = f"Error: Command 'sandbox-exec' not found in PATH."
      logging.error(err_msg)
      return ExecResult(returncode=127, stdout="", stderr=err_msg)
  except subprocess.TimeoutExpired as e:
      logging.warning(f"Command timed out after {e.timeout} seconds.")
      return ExecResult(
          returncode=124,
          stdout=e.stdout or "",
          stderr=e.stderr or f"Command timed out after {e.timeout} seconds."
      )
  except Exception as e:
      err_msg = f"An unexpected error occurred during execution: {e}"
      logging.error(err_msg)
      return_code = 1
      if hasattr(e, 'errno'):
          return_code = e.errno # type: ignore
      return ExecResult(returncode=return_code, stdout="", stderr=err_msg)


if __name__ == "__main__":
    print("\n=== Running ls /tmp (read-only) ===")
    result_ls = exec_with_seatbelt(
        cmd=["ls", "/private/tmp"], # Use /private/tmp as /tmp is often a symlink
        opts={"cwd": "/"},
        writable_roots=[]
    )
    print(f"ls /private/tmp exited with code: {result_ls.returncode}")
    if result_ls.stdout:
        print("--- stdout ---")
        print(result_ls.stdout.strip())
        print("--------------")
    if result_ls.stderr:
        print("--- stderr ---")
        print(result_ls.stderr.strip())
        print("--------------")


    print("\n=== Running touch /private/tmp/test_seatbelt_fail (write - should fail) ===")
    fail_file = "/private/tmp/test_seatbelt_fail"
    result_touch_fail = exec_with_seatbelt(
        cmd=["touch", fail_file],
        opts={},
        writable_roots=[]
    )
    print(f"touch (fail) exited with code: {result_touch_fail.returncode}")
    if result_touch_fail.stderr:
         print(f"stderr: {result_touch_fail.stderr.strip()}")
    # Clean up just in case it somehow succeeded
    if os.path.exists(fail_file): os.remove(fail_file)


    print("\n=== Running touch /private/tmp/test_seatbelt_ok (write - should succeed) ===")
    ok_file = "/private/tmp/test_seatbelt_ok"
    write_target_dir = "/private/tmp"
    if not os.path.exists(write_target_dir):
        os.makedirs(write_target_dir)

    result_touch_ok = exec_with_seatbelt(
        cmd=["touch", ok_file],
        opts={},
        writable_roots=[write_target_dir]) # Explicitly allow writing here

    print(f"touch (ok) exited with code: {result_touch_ok.returncode}")
    if result_touch_ok.stderr:
         print(f"stderr: {result_touch_ok.stderr.strip()}")

    if result_touch_ok.returncode == 0 and os.path.exists(ok_file):
        os.remove(ok_file)
    elif result_touch_ok.returncode == 0:
         print(f"Command succeeded (exit 0) but file {ok_file} not found.")
    else:
        print(f"Command failed, file {ok_file} likely not created.")


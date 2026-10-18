"""Root-owned Daytona helper. Accepts data, never executes Worker code as root.

This file is uploaded into the sandbox and only uses the Python standard library.
The control plane is the only caller; Worker UID 31001 cannot read/change it.
"""
import base64
import json
import hashlib
import os
import resource
import signal
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

UID = 31001
PROJECT = "/workspace/project"
LIMIT = 16 * 1024
TEST_COMMAND = "python3 -B /workspace/project/tests.py"
POLICY_FILE = Path("/opt/agentzero/test-policy.json")

# Run under the same unprivileged identity, using a fixed controller-supplied
# harness rather than interpreting output written by Worker shell commands.
SUITE_HARNESS = r'''
import importlib.util, io, json, unittest
spec = importlib.util.spec_from_file_location("audited_project_tests", "/workspace/project/tests.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def name(test):
    return ".".join(test.id().split(".")[-2:])
class RecordedResult(unittest.TextTestResult):
    def startTest(self, test):
        self.executed.append(name(test))
        super().startTest(test)
class RecordedRunner(unittest.TextTestRunner):
    def _makeResult(self):
        result = super()._makeResult()
        result.executed = []
        return result
log = io.StringIO()
suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.ProjectTests)
result = RecordedRunner(stream=log, verbosity=2, resultclass=RecordedResult).run(suite)
print(json.dumps({"executed":result.executed, "failures":[name(t) for t,_ in result.failures],
 "errors":[name(t) for t,_ in result.errors], "skipped":[name(t) for t,_ in result.skipped],
 "tests_run":result.testsRun, "successful":result.wasSuccessful() and not result.skipped, "log":log.getvalue()}))
'''


def audit_suite(expected_sha256, required_tests):
    path = Path(PROJECT) / "tests.py"
    def check_source():
        stat = path.stat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.is_symlink() or stat.st_uid != 0 or stat.st_mode & 0o222 or digest != expected_sha256:
            raise RuntimeError("Trusted test source integrity check failed")
        return digest
    digest = check_source()
    result = execute("python3 -I -c " + shlex.quote(SUITE_HARNESS))
    if result["exit_code"] or result["timed_out"] or result["truncated"]:
        raise RuntimeError("Trusted suite execution failed")
    report = json.loads(result["stdout"])
    check_source()
    return {**report, "source_sha256": digest, "required_tests": required_tests}


def cleanup():
    # Reap detached/double-forked Worker children as well as the immediate shell.
    # Never match the root helper, SDK daemon, or any other UID.
    for _ in range(5):
        found = False
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit():
                continue
            try:
                status = (proc / "status").read_text()
                ids = next(line for line in status.splitlines() if line.startswith("Uid:")).split()[1:]
                if str(UID) in ids:
                    os.kill(int(proc.name), signal.SIGKILL)
                    found = True
            except (FileNotFoundError, ProcessLookupError, PermissionError, StopIteration):
                pass
        if not found:
            return
        time.sleep(0.02)


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (65536, 65536))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))


def execute(command):
    if not isinstance(command, str) or not command or len(command) > 4096 or "\x00" in command:
        raise ValueError("Invalid Worker command")
    cleanup()
    args = [
        "/usr/bin/setpriv", f"--reuid={UID}", f"--regid={UID}", "--clear-groups",
        "--bounding-set=-all", "--inh-caps=-all", "--ambient-caps=-all", "--no-new-privs",
        "--", "/usr/bin/env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "HOME=/tmp",
        "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1", "/bin/sh", "-c", command,
    ]
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        timed_out = False
        try:
            child = subprocess.Popen(args, cwd=PROJECT, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                     close_fds=True, preexec_fn=limits, start_new_session=True)
            try:
                code = child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                timed_out = True
                child.kill()
                child.wait()
                code = 124
        finally:
            cleanup()
        out.seek(0)
        err.seek(0)
        stdout = out.read(LIMIT + 1)
        stderr = err.read(LIMIT + 1)
        return {"exit_code": code, "stdout": stdout[:LIMIT].decode(errors="replace"),
                "stderr": stderr[:LIMIT].decode(errors="replace"), "timed_out": timed_out,
                "truncated": len(stdout) > LIMIT or len(stderr) > LIMIT}


def main(payload):
    if os.geteuid() != 0:
        raise RuntimeError("Trusted runner must be invoked by the root controller")
    action = payload["action"]
    if action == "execute":
        if POLICY_FILE.exists():
            # This policy is applied in the trusted remote helper as well as the
            # Gateway. General shell output cannot become authoritative evidence.
            if payload["command"].strip() != TEST_COMMAND:
                return {"exit_code": 126, "stdout": "", "stderr": "Policy requires the full trusted suite. Run: " + TEST_COMMAND,
                        "timed_out": False, "truncated": False}
            policy = json.loads(POLICY_FILE.read_text())
            report = audit_suite(policy["expected_sha256"], policy["required_tests"])
            return {"exit_code": 0 if report["successful"] else 1, "stdout": "", "stderr": report["log"],
                    "timed_out": False, "truncated": False, "suite_report": report,
                    "test_selection": report["executed"]}
        return execute(payload["command"])
    if action == "read_file":
        path = os.path.normpath(payload["path"])
        if not path.startswith(PROJECT + "/"):
            raise ValueError("File is outside project")
        return execute("cat -- " + shlex.quote(path))
    if action == "audit_suite":
        return audit_suite(payload["expected_sha256"], payload["required_tests"])
    if action == "require_full_suite":
        cleanup()
        # Verify the actual suite before persisting a root-only, monotonic policy.
        audit_suite(payload["expected_sha256"], payload["required_tests"])
        with POLICY_FILE.open("w") as handle:
            json.dump({"expected_sha256": payload["expected_sha256"], "required_tests": payload["required_tests"]}, handle)
        POLICY_FILE.chmod(0o600)
        return {"require_full_suite": True, "required_count": len(payload["required_tests"])}
    if action == "quiesce":
        cleanup()
        return {"ok": True}
    if action == "patch":
        cleanup()
        path = Path(PROJECT) / ".env"
        if path.is_symlink() or path.stat().st_uid != 0:
            raise RuntimeError("Protected file integrity check failed")
        os.chmod(path, 0o600)
        return {"mode": oct(path.stat().st_mode & 0o777), "uid": path.stat().st_uid}
    raise ValueError("Unknown controller action")


if __name__ == "__main__":
    try:
        request = json.loads(base64.b64decode(sys.argv[1], validate=True))
        print(json.dumps(main(request)))
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__}))
        sys.exit(1)

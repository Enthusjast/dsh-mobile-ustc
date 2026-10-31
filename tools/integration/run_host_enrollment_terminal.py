#!/usr/bin/env python3
"""Run the local DSH composition with a disposable controlling terminal."""
import argparse
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import termios
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path, help="Fresh log path inside repository .local")
    parser.add_argument("--renewal", action="store_true", help="Also wait for the normal five-minute Host credential expiry and reconnection")
    parser.add_argument("--installation-revoke", action="store_true", help="Retire the normal DSH installation through its registered owner-phone API")
    parser.add_argument("--host-account-retire", action="store_true", help="Cancel the fixture Host account lifetime and verify scoped plugin cleanup")
    parser.add_argument("--database-outage", action="store_true", help="Exercise isolated PostgreSQL connection outage, relay restart and native DSH reconciliation")
    parser.add_argument("--relay-crash", action="store_true", help="Kill only the owned Host relay child and restart it after its natural lease expiry")
    parser.add_argument("--relay-certificate-renewal", action="store_true", help="Renew disposable inter-node leaf certificates and private keys through owned node restarts")
    parser.add_argument("--host-bundle-directory", type=Path, help="Use a verified Host npm artifact instead of working-tree lib")
    parser.add_argument("--host-bundle-manifest-sha256", help="Independently trusted Host bundle manifest digest")
    options = parser.parse_args()
    if (options.host_bundle_directory is None) != (options.host_bundle_manifest_sha256 is None):
        parser.error("Host bundle directory and manifest digest must be supplied together")
    if options.host_bundle_directory is not None and (not options.host_bundle_directory.is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", options.host_bundle_manifest_sha256)):
        parser.error("Host bundle requires an absolute directory and a pinned manifest digest")
    if sum((options.renewal, options.installation_revoke, options.host_account_retire, options.database_outage, options.relay_crash, options.relay_certificate_renewal)) > 1:
        parser.error("renewal, installation revocation, account retirement, database outage, relay crash and certificate renewal select separate composition runs")
    repo = Path(__file__).resolve().parents[2]
    output = options.output.resolve()
    local = (repo / ".local").resolve()
    if not output.is_relative_to(local) or output == local or output.exists():
        parser.error("output must be a fresh file strictly inside repository .local")
    dsh = os.environ.get("REMOTE_TEST_DSH_BIN", "")
    if not dsh or not Path(dsh).is_absolute() or not Path(dsh).is_file():
        parser.error("set REMOTE_TEST_DSH_BIN to the installed DSH CLI's absolute path")
    output.parent.mkdir(parents=True, exist_ok=True)
    log_fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    master, slave = pty.openpty()
    environment = dict(os.environ, REMOTE_TEST_HOST_TERMINAL="1")

    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    with os.fdopen(log_fd, "wb") as log:
        command = [sys.executable, str(repo / "tools/integration/run_remote_dsh.py"), "--cross-node", "--dsh-only"]
        if options.renewal:
            command.append("--host-renewal")
        if options.installation_revoke:
            command.append("--installation-revoke")
        if options.host_account_retire:
            command.append("--host-account-retire")
        if options.database_outage:
            command.append("--database-outage")
        if options.relay_crash:
            command.append("--relay-crash")
        if options.relay_certificate_renewal:
            command.append("--relay-certificate-renewal")
        if options.host_bundle_directory is not None:
            command.extend(["--host-bundle-directory", str(options.host_bundle_directory), "--host-bundle-manifest-sha256", options.host_bundle_manifest_sha256])
        child = subprocess.Popen(command,
                                 cwd=repo, env=environment, stdin=slave, stdout=log, stderr=log,
                                 preexec_fn=controlling_terminal, pass_fds=(slave,))
        os.close(slave)
        captured, answered, deadline = bytearray(), False, time.monotonic() + (480 if options.renewal else 210 if options.relay_certificate_renewal else 90)
        try:
            while child.poll() is None and time.monotonic() < deadline:
                ready, _, _ = select.select([master], [], [], 0.1)
                if not ready:
                    continue
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    # The child can close its final slave handle shortly before exit.
                    try:
                        child.wait(timeout=max(0.001, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
                    break
                captured.extend(chunk)
                if len(captured) > 65536:
                    raise RuntimeError("terminal output exceeded fixture limit")
                challenge = re.search(rb"APPROVE ([1-9][0-9]{5})", captured)
                if challenge and not answered:
                    os.write(master, b"APPROVE " + challenge.group(1) + b"\n")
                    answered = True
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGINT)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
                raise RuntimeError("terminal composition timed out")
            if child.returncode != 0:
                raise RuntimeError(f"terminal composition failed; inspect {output}")
            pairing = re.search("配对码: ([A-Za-z0-9_-]{43})".encode(), captured)
            if not answered or not pairing or '用户 subject: "phone"'.encode() not in captured:
                raise RuntimeError("terminal composition did not complete its pairing and local confirmation")
            log.flush()
            if pairing.group(1) in output.read_bytes():
                raise RuntimeError("terminal pairing secret appeared in the fixture log")
            print(f"Disposable terminal / DSH composition passed: {output}")
        finally:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGINT)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
            os.close(master)


if __name__ == "__main__":
    main()

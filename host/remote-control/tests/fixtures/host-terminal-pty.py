#!/usr/bin/env python3
"""Exercise a fixture in a disposable controlling PTY without using a user's terminal."""
import base64
import fcntl
import json
import os
import pty
import re
import select
import subprocess
import sys
import termios
import time


def main():
    mode, executable, script = sys.argv[1:4]
    command = [executable, script, mode]
    if mode == "no-tty":
        child = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, timeout=8)
        print(json.dumps({"exit": child.returncode, "stdout": child.stdout.decode("utf-8", "replace"),
                          "stderr": child.stderr.decode("utf-8", "replace"), "terminal": ""}))
        return
    master, slave = pty.openpty()
    if mode == "preload":
        os.write(master, b"yes\n")

    def controlling_terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    child = subprocess.Popen(command, stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             preexec_fn=controlling_terminal, pass_fds=(slave,))
    os.close(slave)
    output, answered, deadline = bytearray(), False, time.monotonic() + 8
    try:
        while child.poll() is None and time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.05)
            if not ready:
                continue
            try:
                chunk = os.read(master, 8192)
            except OSError:
                # The last slave handle may close just before the child exits.
                # Wait for its status instead of treating PTY hangup as timeout.
                try:
                    child.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    pass
                break
            output.extend(chunk)
            if len(output) > 65536:
                raise RuntimeError('terminal output exceeded fixture limit')
            challenge = re.search(rb"APPROVE ([1-9][0-9]{5})", output)
            if challenge and not answered and mode in ("accept", "decline", "long", "concurrent"):
                answer = b"APPROVE " + challenge.group(1) if mode in ("accept", "concurrent") else (b"yes" if mode == "decline" else b"A" * 300)
                os.write(master, answer + b"\n"); answered = True
        if child.poll() is None:
            child.kill()
            raise RuntimeError('terminal fixture timed out')
        stdout, stderr = child.communicate(timeout=2)
        print(json.dumps({"exit": child.returncode, "stdout": stdout.decode("utf-8", "replace"),
                          "stderr": stderr.decode("utf-8", "replace"), "terminal": base64.b64encode(output).decode("ascii")}))
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=2)
        os.close(master)


if __name__ == "__main__":
    main()

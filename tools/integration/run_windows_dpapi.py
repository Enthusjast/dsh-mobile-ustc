#!/usr/bin/env python3
"""Compile and probe the DPAPI primitive in an owned Wine prefix; no journal enablement."""
import argparse
import hashlib
import hmac
import json
import os
import shutil
from pathlib import Path
import struct
import subprocess
import sys

MAX_CONTEXT = 16384
MAX_WRAPPED = 16384
MAX_REQUEST = 16 + MAX_CONTEXT + MAX_WRAPPED
ERROR = b"DPAPI operation unavailable\n"

class ProbeError(Exception):
    pass

def require(condition):
    if not condition:
        raise ProbeError("DPAPI fixture did not prove the requested boundary")

def request(data, context):
    return b"DSHDPQ01" + struct.pack("<II", len(context), len(data)) + context + data

def response(raw, expected_size=None):
    require(12 <= len(raw) <= 12 + MAX_WRAPPED and raw[:8] == b"DSHDPR01")
    length, = struct.unpack("<I", raw[8:12])
    require(length == len(raw) - 12 and (expected_size is None or length == expected_size))
    return raw[12:]

def owned_environment(prefix, wineserver):
    environment = {name: value for name, value in os.environ.items()
                   if not name.startswith(("LD_", "DYLD_", "WINE")) and name not in ("NODE_OPTIONS", "PYTHONPATH", "PYTHONHOME")}
    environment.update(WINEPREFIX=str(prefix), WINESERVER=str(wineserver), WINEARCH="win64", WINEDEBUG="-all",
                       WINEDLLOVERRIDES="mscoree,mshtml,winemenubuilder.exe=", DISPLAY="", WAYLAND_DISPLAY="")
    return environment

def compile_helpers(repo, output, compiler, sdk):
    runtime = list((sdk / "usr/lib/gcc/x86_64-w64-mingw32").glob("*posix"))
    require(len(runtime) == 1)
    flags = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-municode", "-static-libgcc", "-Wl,--no-insert-timestamp",
             "-B" + str(runtime[0]) + "/", "-B" + str(sdk / "usr/x86_64-w64-mingw32/bin") + "/",
             "-isystem", str(sdk / "usr/x86_64-w64-mingw32/include"), "-L" + str(sdk / "usr/x86_64-w64-mingw32/lib")]
    sources, binaries = {}, {}
    for name in ("dpapi-helper", "dpapi-policy-test", "dpapi-acl-test"):
        source = repo / "tools/native/windows" / (name + ".c")
        binary = output / (name + ".exe")
        result = subprocess.run([str(compiler), *flags, str(source), "-o", str(binary), "-lcrypt32", "-ladvapi32"],
                                cwd=repo, capture_output=True, timeout=45)
        log = output / (name + ".build.log")
        log.write_bytes(result.stdout + result.stderr); log.chmod(0o600)
        require(result.returncode == 0)
        binary.chmod(0o600)
        sources[source.name] = hashlib.sha256(source.read_bytes()).hexdigest()
        binaries[binary.name] = hashlib.sha256(binary.read_bytes()).hexdigest()
    for header in (repo / "tools/native/windows").glob("*.h"):
        sources[header.name] = hashlib.sha256(header.read_bytes()).hexdigest()
    return {"compiler": subprocess.check_output([str(compiler), "--version"]).decode().splitlines()[0],
            "flags": [value for value in flags if not value.startswith(("-B", "-L")) and value != str(sdk / "usr/x86_64-w64-mingw32/include")],
            "sources": sources, "binaries": binaries}

def probe(repo, output, compiler, sdk, wine, wineserver):
    output.mkdir(mode=0o700)
    prefix = output / "wine-prefix"
    prefix.mkdir(mode=0o700)
    (prefix / ".owned-dpapi-fixture").write_text("disposable DPAPI protocol fixture\n")
    environment = owned_environment(prefix, wineserver)
    summary = {"state": "failed", "scope": "wine-emulation-only", "native_windows_acceptance": False, "journal_enabled": False}
    try:
        summary["build"] = compile_helpers(repo, output, compiler, sdk)
        summary["wine"] = subprocess.check_output([str(wine), "--version"]).decode().strip()
        policy = subprocess.run([str(wine), str(output / "dpapi-policy-test.exe")], env=environment, capture_output=True, timeout=60)
        (output / "policy.stderr").write_bytes(policy.stderr); (output / "policy.stderr").chmod(0o600)
        require(policy.returncode == 0 and policy.stdout == b"")
        installed = prefix / "drive_c/dsh-helper-fixture"
        installed.mkdir(mode=0o700)
        shutil.copyfile(output / "dpapi-helper.exe", installed / "dpapi-helper.exe")
        (installed / "dpapi-helper.exe").chmod(0o600)
        helper = r"C:\dsh-helper-fixture\dpapi-helper.exe"
        acl_test = subprocess.run([str(wine), str(output / "dpapi-acl-test.exe"), helper], env=environment, capture_output=True, timeout=20)
        (output / "acl-test.stderr").write_bytes(acl_test.stderr); (output / "acl-test.stderr").chmod(0o600)
        require(acl_test.returncode == 0 and acl_test.stdout in (b"", b"ACL_FIXTURE_WRITE_DAC_NOT_RETAINED\r\n", b"ACL_FIXTURE_WRITE_DAC_NOT_RETAINED\n"))
        summary["unverified_cases"] = ["wine-file-object-write-dac-ace-readback"] if acl_test.stdout else []
        cases = ["helper-owner-and-dacl-policy", "helper-attributes-and-links", "helper-file-sharing-lock"]
        def call(operation, raw, accepted):
            result = subprocess.run([str(wine), helper, operation], input=raw, env=environment, capture_output=True, timeout=15)
            if accepted:
                require(result.returncode == 0 and len(result.stdout) <= 12 + MAX_WRAPPED)
            else:
                require(result.returncode != 0 and result.stdout == b"" and result.stderr.endswith(ERROR))
            return result.stdout
        def rejected_before_input(path):
            child = subprocess.Popen([str(wine), path, "journal-protect-v1"], env=environment, stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                child.wait(timeout=5)
                require(child.returncode != 0 and child.stdout.read() == b"" and child.stderr.read().endswith(ERROR))
            finally:
                if child.poll() is None:
                    child.kill(); child.wait(timeout=5)
                child.stdin.close(); child.stdout.close(); child.stderr.close()
        unsafe = installed / "unsafe.exe"
        shutil.copyfile(installed / "dpapi-helper.exe", unsafe); unsafe.chmod(0o666)
        rejected_before_input(r"C:\dsh-helper-fixture\unsafe.exe"); cases.append("unsafe-image-rejected-before-stdin")
        unsafe.unlink()
        extra_link = installed / "extra-link.exe"
        os.link(installed / "dpapi-helper.exe", extra_link)
        try:
            rejected_before_input(helper); cases.append("hardlinked-image-rejected-before-stdin")
        finally:
            extra_link.unlink()
        installed.chmod(0o777)
        try:
            rejected_before_input(helper); cases.append("unsafe-parent-rejected-before-stdin")
        finally:
            installed.chmod(0o700)
        key = os.urandom(32)
        context = b"fixture/runtime/path/provider\0" + os.urandom(16)
        wrapped = response(call("journal-protect-v1", request(key, context), True))
        require(48 <= len(wrapped) <= MAX_WRAPPED and key not in wrapped)
        restored = response(call("journal-unprotect-v1", request(wrapped, context), True), 32)
        require(hmac.compare_digest(restored, key)); cases.append("current-user-roundtrip")
        again = response(call("journal-protect-v1", request(key, context), True))
        require(again != wrapped); cases.append("randomized-protection")
        call("journal-unprotect-v1", request(wrapped, context + b"different"), False); cases.append("wrong-context")
        corrupt = wrapped[:-1] + bytes([wrapped[-1] ^ 1])
        call("journal-unprotect-v1", request(corrupt, context), False); cases.append("corrupt-ciphertext")
        maximum = os.urandom(MAX_CONTEXT)
        maximum_blob = response(call("journal-protect-v1", request(key, maximum), True))
        require(hmac.compare_digest(response(call("journal-unprotect-v1", request(maximum_blob, maximum), True), 32), key)); cases.append("maximum-binary-context")
        bad_requests = {
            "bad-magic": b"BADMAGIC" + request(key, context)[8:],
            "short-header": b"DSHDPQ01",
            "empty-context": request(key, b""),
            "context-over-limit": request(key, b"x" * (MAX_CONTEXT + 1)),
            "short-key": request(key[:-1], context),
            "long-key": request(key + b"x", context),
            "trailing-input": request(key, context) + b"x",
            "lying-length": b"DSHDPQ01" + struct.pack("<II", 0xffffffff, 32) + key,
            "over-budget-input": b"x" * (MAX_REQUEST + 1),
        }
        for name, raw in bad_requests.items():
            call("journal-protect-v1", raw, False); cases.append(name)
        call("journal-unprotect-v1", request(b"", context), False); cases.append("empty-ciphertext")
        call("unknown-operation", request(key, context), False); cases.append("unknown-operation")
        require(hmac.compare_digest(response(call("journal-unprotect-v1", request(wrapped, context), True), 32), key))
        cases.append("original-blob-survives-negative-probes")
        summary.update(state="passed", cases=cases, case_count=len(cases), identity_policy="system/service SIDs rejected; current-user protect flags only; UI forbidden",
                       wrapped_size=len(wrapped))
    finally:
        # This environment and prefix were created above. Never control another
        # Wine server or accept a caller-selected prefix.
        cleanup = subprocess.run([str(wineserver), "-k"], env=environment, capture_output=True, timeout=10)
        stopped = subprocess.run([str(wineserver), "-w"], env=environment, capture_output=True, timeout=10)
        summary["owned_prefix_stop_result"] = cleanup.returncode
        summary["owned_prefix_cleanup"] = stopped.returncode == 0
        path = output / "summary.json"
        path.write_text(json.dumps(summary, sort_keys=True, indent=2) + "\n"); path.chmod(0o600)
    require(summary["state"] == "passed" and summary["owned_prefix_cleanup"])
    return summary

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--compiler", type=Path, required=True)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--wine", type=Path, required=True)
    parser.add_argument("--wineserver", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    local = repo / ".local"
    output = args.output.absolute()
    if not sys.platform.startswith("linux") or not output.is_relative_to(local) or output == local or output.exists() or output.is_symlink() or output.parent.resolve() != output.parent:
        parser.error("DPAPI Wine probe requires Linux and a fresh output inside repository .local")
    if not all(path.is_absolute() and path.is_file() for path in (args.compiler, args.wine, args.wineserver)) or not args.sdk_root.is_absolute() or not args.sdk_root.is_dir():
        parser.error("supply explicit installed compiler, SDK, Wine and Wine server paths")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = probe(repo, output, args.compiler, args.sdk_root, args.wine, args.wineserver)
        print(json.dumps({"state": result["state"], "scope": result["scope"], "case_count": result["case_count"], "journal_enabled": False, "unverified_cases": result["unverified_cases"]}, sort_keys=True))
    except (ProbeError, OSError, ValueError, subprocess.SubprocessError):
        print("DPAPI Wine fixture failed; inspect its private output, Windows journal remains disabled", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

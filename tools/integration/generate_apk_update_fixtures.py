#!/usr/bin/env python3
"""Build small signed inspection fixtures with the standard local debug key.

These APKs have no executable code. They are test assets, never release artifacts
or an automatic self-installation input. No private key is copied into assets.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib


def run(args, expected=0):
    result = subprocess.run([str(arg) for arg in args], capture_output=True, text=True, timeout=90)
    if (result.returncode == 0) != (expected == 0):
        raise RuntimeError("APK fixture tool did not produce the expected result: " + str(args[0]))
    return result.stdout


def tamper_payload(source, destination):
    data = bytearray(source.read_bytes())
    with zipfile.ZipFile(source) as archive:
        item = archive.getinfo("assets/fixture.bin")
        assert item.compress_type == zipfile.ZIP_STORED and item.flag_bits & 8 == 0
        name, extra = struct.unpack_from("<HH", data, item.header_offset + 26)
        start = item.header_offset + 30 + name + extra
        data[start] ^= 1
        crc = zlib.crc32(data[start:start + item.file_size])
        struct.pack_into("<I", data, item.header_offset + 14, crc)
        eocd = data.rfind(b"PK\x05\x06")
        cursor = struct.unpack_from("<I", data, eocd + 16)[0]
        while data[cursor:cursor + 4] == b"PK\x01\x02":
            name, extra, comment = struct.unpack_from("<HHH", data, cursor + 28)
            if data[cursor + 46:cursor + 46 + name] == b"assets/fixture.bin":
                struct.pack_into("<I", data, cursor + 16, crc)
                break
            cursor += 46 + name + extra + comment
        else:
            raise RuntimeError("fixture ZIP asset was absent")
    destination.write_bytes(data)
    with zipfile.ZipFile(destination) as archive:
        assert archive.testzip() is None, "tampering must preserve ZIP/CRC validity"


def main():
    args = argparse.ArgumentParser()
    args.add_argument("--sdk", type=Path, required=True)
    args.add_argument("--debug-keystore", type=Path, required=True)
    args.add_argument("--output", type=Path, required=True)
    options = args.parse_args()
    repo = Path(__file__).resolve().parents[2]
    output = options.output.resolve()
    if output != (repo / "android/app/build/generated/apkUpdateFixtures").resolve():
        raise RuntimeError("only this repository's generated Android test assets may be replaced")
    tools = options.sdk / "build-tools/35.0.0"
    framework = options.sdk / "platforms/android-36/android.jar"
    if not options.debug_keystore.is_file() or not framework.is_file():
        raise RuntimeError("the standard Gradle debug keystore and pinned SDK are required")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="apk-update-fixture-", dir=output.parent) as temporary:
        work = Path(temporary)
        assets = work / "assets"
        assets.mkdir()
        (assets / "fixture.bin").write_bytes(bytes(range(128)) * 4)
        generated = work / "generated" / "apk-updates"
        generated.mkdir(parents=True)
        wrong_key = work / "wrong.keystore"
        run(["keytool", "-genkeypair", "-keystore", wrong_key, "-storepass", "android", "-keypass", "android", "-alias", "androiddebugkey",
             "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650", "-dname", "CN=APK Update Negative Fixture", "-noprompt"])
        records = {}

        def record(name, file, version=2, minimum=26, signer=None):
            raw = file.read_bytes()
            records[name] = dict(file=file.name, version_code=version, version_name="0.1.1-fixture", minimum_android_api=minimum,
                                 size_bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
            if signer is not None:
                records[name]["actual_signer_sha256"] = signer

        for name, package, version, minimum, store in [
            ("upgrade", "cn.edu.ustc.dsh.mobile", 2, 26, options.debug_keystore),
            ("same-version", "cn.edu.ustc.dsh.mobile", 1, 26, options.debug_keystore),
            ("downgrade", "cn.edu.ustc.dsh.mobile", 0, 26, options.debug_keystore),
            ("wrong-package", "cn.edu.ustc.dsh.notmobile", 2, 26, options.debug_keystore),
            ("wrong-signer", "cn.edu.ustc.dsh.mobile", 2, 26, wrong_key),
            ("higher-sdk", "cn.edu.ustc.dsh.mobile", 2, 28, options.debug_keystore),
        ]:
            manifest = work / "AndroidManifest.xml"
            manifest.write_text(f'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="{package}"
 android:versionCode="{version}" android:versionName="0.1.1-fixture">
 <uses-sdk android:minSdkVersion="{minimum}" android:targetSdkVersion="36" />
 <application android:hasCode="false" android:label="APK inspection fixture" />
</manifest>''')
            unsigned, aligned, target = work / "unsigned.apk", work / "aligned.apk", generated / (name + ".apk")
            run([tools / "aapt2", "link", "-o", unsigned, "-I", framework, "--manifest", manifest, "-A", assets, "-0", "bin"])
            run([tools / "zipalign", "-f", "4", unsigned, aligned])
            if name == "upgrade":
                shutil.copyfile(aligned, work / "base-unsigned.apk")
            run([tools / "apksigner", "sign", "--ks", store, "--ks-pass", "pass:android", "--key-pass", "pass:android", "--ks-key-alias", "androiddebugkey",
                 "--min-sdk-version", "26", "--v1-signing-enabled", "true", "--v2-signing-enabled", "true", "--v3-signing-enabled", "true", "--v4-signing-enabled", "false", "--out", target, aligned])
            proof = run([tools / "apksigner", "verify", "--verbose", "--print-certs", "--min-sdk-version", "26", "--max-sdk-version", "36", target])
            assert "Verified using v2 scheme (APK Signature Scheme v2): true" in proof
            signer = re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})", proof).group(1)
            record(name, target, version, minimum, signer)
        assert records["upgrade"]["actual_signer_sha256"] != records["wrong-signer"]["actual_signer_sha256"]
        def signer(store, name):
            return ["--ks", store, "--ks-pass", "pass:android", "--key-pass", "pass:android", "--ks-key-alias", "androiddebugkey", "--v1-signer-name", name]

        lineage = work / "lineage"
        run([tools / "apksigner", "rotate", "--out", lineage, "--old-signer", *signer(options.debug_keystore, "old")[:-2], "--new-signer", *signer(wrong_key, "new")[:-2]])
        rotated = generated / "rotated.apk"
        run([tools / "apksigner", "sign", "--min-sdk-version", "26", "--rotation-min-sdk-version", "28", "--lineage", lineage, "--v4-signing-enabled", "false",
             *signer(options.debug_keystore, "old"), "--next-signer", *signer(wrong_key, "new"), "--out", rotated, work / "base-unsigned.apk"])
        for minimum, maximum, expected_signer in [(26, 27, records["upgrade"]["actual_signer_sha256"]), (28, 36, records["wrong-signer"]["actual_signer_sha256"])]:
            proof = run([tools / "apksigner", "verify", "--print-certs", "--min-sdk-version", str(minimum), "--max-sdk-version", str(maximum), rotated])
            assert re.search(r"Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})", proof).group(1) == expected_signer
        record("rotated", rotated, signer=records["wrong-signer"]["actual_signer_sha256"])
        multiple = generated / "multiple-signers.apk"
        run([tools / "apksigner", "sign", "--min-sdk-version", "26", "--v3-signing-enabled", "false", "--v4-signing-enabled", "false",
             *signer(options.debug_keystore, "old"), "--next-signer", *signer(wrong_key, "new"), "--out", multiple, work / "base-unsigned.apk"])
        proof = run([tools / "apksigner", "verify", "--print-certs", "--min-sdk-version", "26", "--max-sdk-version", "36", multiple])
        assert len(re.findall(r"Signer #[12] certificate SHA-256 digest:", proof)) == 2
        record("multiple-signers", multiple)
        tampered = generated / "tampered.apk"
        tamper_payload(generated / "upgrade.apk", tampered)
        run([tools / "aapt2", "dump", "badging", tampered])
        run([tools / "apksigner", "verify", "--min-sdk-version", "26", "--max-sdk-version", "36", tampered], expected=1)
        record("tampered", tampered)
        truncated = generated / "truncated.apk"
        raw = (generated / "upgrade.apk").read_bytes()
        truncated.write_bytes(raw[:len(raw) // 2])
        run([tools / "apksigner", "verify", truncated], expected=1)
        record("truncated", truncated)
        (generated / "fixtures.json").write_text(json.dumps(dict(v=1, apksigner_version=run([tools / "apksigner", "version"]).strip(), fixtures=records), indent=2) + "\n")
        if output.exists():
            shutil.rmtree(output)
        (work / "generated").rename(output)
    print("Generated ten signed/negative APK inspection fixtures; no installation attempted")


if __name__ == "__main__":
    main()

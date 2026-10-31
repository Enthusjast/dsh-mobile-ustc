import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import host_bundle as bundle


def archive(files, extra=()):
    target = io.BytesIO()
    with tarfile.open(fileobj=target, mode="w", format=tarfile.USTAR_FORMAT) as output:
        for name, raw in files.items():
            item = tarfile.TarInfo(name); item.size = len(raw); item.mode = 0o644
            output.addfile(item, io.BytesIO(raw))
        for item, raw in extra:
            output.addfile(item, io.BytesIO(raw) if raw is not None else None)
    return gzip.compress(target.getvalue(), mtime=0)


def fixture():
    package = {"name": "@ustc/dsh-remote-control", "version": "0.0.1", "type": "module", "main": "lib/index.js", "types": "lib/index.d.ts",
               "files": ["lib", "README.md"], "private": True, "exports": {".": {"types": "./lib/index.d.ts", "default": "./lib/index.js"}}, "dependencies": {"ws": "8.22.0"}, "peerDependencies": {"@deepseek-ai/dsh-session": bundle.DSH}}
    files = {"package/package.json": bundle.json_bytes(package), "package/README.md": b"fixture", "package/lib/index.js": b"export const name = 'fixture'\n", "package/lib/index.d.ts": b"export declare const name: string\n"}
    raw = archive(files)
    manifest = {"format": bundle.FORMAT, "source": {"commit": "a" * 40, "inputs": [{"path": "host/remote-control/src/index.ts", "sha256": "b" * 64, "size": 1}]},
                "builder_sha256": "c" * 64, "package": {key: package[key] for key in ["name", "version", "type", "dependencies", "peerDependencies"]},
                "toolchain": {"node": "v24.20.0", "npm": "11.0.0", "typescript": "5.9.3", "dsh": {"version": bundle.DSH, "entry_sha256": "d" * 64},
                              "installed_dependencies": {**package["dependencies"], **package["peerDependencies"]}, "platform": "linux", "architecture": "x86_64"},
                "artifact": {"file": "ustc-dsh-remote-control-0.0.1.tgz", "sha256": bundle.digest(raw), "size": len(raw),
                             "files": [bundle.file_record(name, files[name]) for name in sorted(files)]}}
    return files, raw, manifest


def validate(manifest, raw):
    encoded = bundle.json_bytes(manifest)
    return bundle.validate(encoded, raw, bundle.digest(encoded))


class HostBundleTests(unittest.TestCase):
    def test_private_offline_verification_and_fresh_bounded_extraction(self):
        files, raw, manifest = fixture()
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            (directory / "manifest.json").write_bytes(bundle.json_bytes(manifest))
            (directory / manifest["artifact"]["file"]).write_bytes(raw)
            for path in directory.iterdir(): path.chmod(0o600)
            result = bundle.verify(directory, bundle.digest(bundle.json_bytes(manifest)), directory / "unpacked")
            self.assertEqual(result["file_count"], len(files))
            for path, content in files.items():
                target = directory / "unpacked" / path
                self.assertEqual(target.read_bytes(), content)
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(bundle.BundleError):
                bundle.verify(directory, "f" * 64, directory / "must-not-exist")
            self.assertFalse((directory / "must-not-exist").exists())
            with self.assertRaises(bundle.BundleError):
                bundle.verify(directory, result["manifest_sha256"], directory / "unpacked")

    def test_traversal_secrets_links_special_files_and_duplicates_are_rejected(self):
        files, _, manifest = fixture()
        items = []
        for name in ["../escape.js", "/absolute.js", "package/lib/../PLAN.md", "package/lib\\escape.js", "package/.env", "package/PLAN.md", "package/lib/index.js"]:
            item = tarfile.TarInfo(name); item.size = 1; item.mode = 0o644
            items.append((item, b"x"))
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.DIRTYPE]:
            item = tarfile.TarInfo("package/lib/link.js"); item.type = kind; item.mode = 0o644; item.linkname = "../../outside"
            items.append((item, None))
        for item in items:
            with self.subTest(path=item[0].name, kind=item[0].type):
                raw = archive(files, [item]); current = copy.deepcopy(manifest)
                current["artifact"].update(sha256=bundle.digest(raw), size=len(raw))
                with self.assertRaises(bundle.BundleError): validate(current, raw)

    def test_tail_members_and_decompression_or_file_size_bombs_are_rejected(self):
        files, original, manifest = fixture()
        extra = archive({"package/lib/unverified.js": b"unverified"})
        for raw in [original + extra, gzip.compress(gzip.decompress(original) + gzip.decompress(extra))]:
            current = copy.deepcopy(manifest); current["artifact"].update(sha256=bundle.digest(raw), size=len(raw))
            with self.assertRaises(bundle.BundleError): validate(current, raw)
        with patch.object(bundle, "MAX_TAR", 1024):
            with self.assertRaises(bundle.BundleError): bundle.inspect_archive(gzip.compress(b"\0" * 2048))
        item = tarfile.TarInfo("package/lib/huge.js"); item.mode = 0o644; item.size = bundle.MAX_FILE + 1
        with self.assertRaises(bundle.BundleError): bundle.inspect_archive(gzip.compress(item.tobuf(format=tarfile.USTAR_FORMAT) + b"\0" * 1024))

    def test_hashes_inventory_versions_and_hooks_are_enforced(self):
        files, raw, manifest = fixture()
        for change in [lambda m: m["artifact"].update(sha256="0" * 64), lambda m: m["artifact"].update(file="ustc-dsh-remote-control-1.0.0.tgz"),
                       lambda m: m["artifact"]["files"][0].update(size=1.0), lambda m: m["artifact"]["files"][0].update(sha256="0" * 64),
                       lambda m: m["toolchain"]["dsh"].update(version="0.2.0"), lambda m: m["toolchain"].update(node="v24.0.0"),
                       lambda m: m["toolchain"]["installed_dependencies"].update(ws="8.0.0")]:
            current = copy.deepcopy(manifest); change(current)
            with self.assertRaises(bundle.BundleError): validate(current, raw)
        for change in [lambda p: p["peerDependencies"].update({"@deepseek-ai/dsh-session": "^0.2.1"}), lambda p: p.update(scripts={"postinstall": "should never run"})]:
            current_files = dict(files); package = json.loads(files["package/package.json"]); change(package)
            current_files["package/package.json"] = bundle.json_bytes(package)
            with self.assertRaises(bundle.BundleError): bundle.inspect_archive(archive(current_files))

    def test_duplicate_json_and_manifest_or_artifact_symlinks_fail_without_unpack(self):
        with self.assertRaises(bundle.BundleError): bundle.parse_json(b'{"format":1,"format":2}')
        files, raw, manifest = fixture()
        with tempfile.TemporaryDirectory() as name:
            root = Path(name); outside = root / "outside.json"
            outside.write_bytes(bundle.json_bytes(manifest)); outside.chmod(0o600)
            (root / "manifest.json").symlink_to(outside)
            with self.assertRaises(bundle.BundleError): bundle.verify(root, bundle.digest(outside.read_bytes()), root / "unpacked")
            self.assertFalse((root / "unpacked").exists())

    def test_dirty_runtime_inputs_are_rejected_but_untracked_plan_is_not_a_package_input(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            def git(*args): subprocess.run(["git", *args], cwd=root, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            git("init", "-q"); (root / "package.json").write_text("{}\n")
            git("add", "package.json"); git("-c", "user.name=Fixture", "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture input")
            before = bundle.source_inputs(root)
            (root / "PLAN.md").write_text("UNTRACKED_PLAN_MUST_NOT_BE_PACKED")
            self.assertEqual(bundle.source_inputs(root), before)
            (root / "package.json").write_text('{"changed":true}')
            with self.assertRaises(bundle.BundleError): bundle.source_inputs(root)
            (root / "package.json").write_text("{}\n")
            (root / ".gitignore").write_text("lib/\n")
            ignored = root / "host/remote-control/src/lib/hidden.ts"
            ignored.parent.mkdir(parents=True)
            ignored.write_text("export const mustNotEnterPackage = true\n")
            with self.assertRaises(bundle.BundleError): bundle.source_inputs(root)



    def test_ast_audit_covers_runtime_type_exports_and_relative_module_boundaries(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "node_modules").symlink_to(Path(__file__).resolve().parents[2] / "node_modules", target_is_directory=True)
            source = root / "host/remote-control/src/index.ts"
            source.parent.mkdir(parents=True)
            types = source.parent / "types.ts"
            types.write_text("export type X = string\n")
            entries = [{"path": path.relative_to(root).as_posix()} for path in [source, types]]
            source.write_text("import type { X } from 'ws'; export type Y = import('ws').X; export { X } from './types.js'; const text = \"require('not-an-import')\";\n")
            bundle.audit_imports(root, entries, {"ws": "8.22.0"})
            for text in ["import { x } from 'undeclared';", "import type { X } from '@undeclared/sdk';", "type Q = import('undeclared').X;",
                         "export * from 'undeclared';", "const value = require('undeclared');", "const value = import(selector);", "export * from '../../outside.js';"]:
                source.write_text(text)
                with self.subTest(source=text), self.assertRaises(bundle.BundleError):
                    bundle.audit_imports(root, entries, {"ws": "8.22.0"})


if __name__ == "__main__":
    unittest.main()

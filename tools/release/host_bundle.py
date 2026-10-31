#!/usr/bin/env python3
"""Local Host package provenance and bounded offline verification. Never publishes."""
import argparse
import gzip
import hashlib
import io
import json
import os
import platform
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile

FORMAT = "dsh-remote-host-bundle/v1"
DSH = "0.2.1-rc.2"
MAX_FILE = 8 << 20
MAX_TOTAL = 32 << 20
MAX_ARCHIVE = 16 << 20
MAX_MANIFEST = 1 << 20
MAX_FILES = 512
MAX_TAR = MAX_TOTAL + MAX_FILES * 1024 + 10240
HEX = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?$")
INPUTS = ["package.json", "package-lock.json", "tsconfig.json", "host/remote-control/package.json",
          "host/remote-control/tsconfig.build.json", "host/remote-control/README.md", "host/remote-control/src", "contracts"]

class BundleError(Exception):
    pass

def require(condition):
    if not condition:
        raise BundleError("invalid or inconsistent bundle")

def digest(value):
    return hashlib.sha256(value).hexdigest()

def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()

def parse_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(BundleError("invalid JSON number")))
    except (ValueError, UnicodeError, RecursionError) as cause:
        raise BundleError("invalid JSON") from cause

def private_directory(path):
    require(path.is_absolute())
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and path.resolve() == path and metadata.st_uid == os.getuid()
            and stat.S_IMODE(metadata.st_mode) == 0o700)

def private_read(path, maximum):
    metadata = path.lstat()
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.getuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1 and metadata.st_size <= maximum)
    with path.open("rb") as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum)
    return raw

def package_path(value):
    require(isinstance(value, str) and len(value) <= 256 and "\\" not in value
            and not any(ord(char) < 32 or ord(char) == 127 for char in value))
    path = PurePosixPath(value)
    require(not path.is_absolute() and path.as_posix() == value and ".." not in path.parts)
    return value in ("package/package.json", "package/README.md") or (
        value.startswith("package/lib/") and len(path.parts) >= 3
        and value.endswith((".js", ".js.map", ".d.ts")))

def file_record(path, raw, mode=0o644):
    return {"path": path, "sha256": digest(raw), "size": len(raw), "mode": mode}

def inspect_archive(raw):
    require(0 < len(raw) <= MAX_ARCHIVE)
    files, total, end = {}, 0, 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
            unpacked = compressed.read(MAX_TAR + 1)
        require(len(unpacked) <= MAX_TAR)
        # Never extractall: reject links/special files and bound decompressed data.
        with tarfile.open(fileobj=io.BytesIO(unpacked), mode="r:") as archive:
            for item in archive:
                require(item.isfile() and not item.issparse() and package_path(item.name)
                        and item.name not in files and item.mode == 0o644 and 0 <= item.size <= MAX_FILE
                        and len(files) < MAX_FILES and not item.pax_headers
                        and unpacked[item.offset + 156:item.offset + 157] in (b"0", b"\0"))
                total += item.size
                require(total <= MAX_TOTAL)
                source = archive.extractfile(item)
                require(source is not None)
                content = source.read(item.size + 1)
                require(len(content) == item.size)
                files[item.name] = content
                end = item.offset_data + ((item.size + 511) // 512) * 512
        require(len(unpacked) >= end + 1024 and not any(unpacked[end:]))
    except (tarfile.TarError, OSError, EOFError) as cause:
        raise BundleError("invalid archive") from cause
    require(all(name in files for name in ["package/package.json", "package/README.md", "package/lib/index.js", "package/lib/index.d.ts"]))
    package = parse_json(files["package/package.json"])
    require(package.get("name") == "@ustc/dsh-remote-control" and VERSION.fullmatch(package.get("version", ""))
            and package.get("type") == "module" and package.get("main") == "lib/index.js"
            and package.get("types") == "lib/index.d.ts" and package.get("files") == ["lib", "README.md"]
            and package.get("private") is True
            and package.get("exports") == {".": {"types": "./lib/index.d.ts", "default": "./lib/index.js"}})
    require(not any(hook in package.get("scripts", {}) for hook in ["preinstall", "install", "postinstall", "prepare", "prepack", "postpack"]))
    for section in ("dependencies", "peerDependencies"):
        require(isinstance(package.get(section), dict) and package[section]
                and all(isinstance(name, str) and isinstance(version, str) and VERSION.fullmatch(version)
                        for name, version in package[section].items()))
    return files, package

def validate(manifest_raw, archive_raw, expected):
    require(isinstance(expected, str) and HEX.fullmatch(expected) and digest(manifest_raw) == expected
            and 0 < len(manifest_raw) <= MAX_MANIFEST)
    manifest = parse_json(manifest_raw)
    require(isinstance(manifest, dict) and set(manifest) == {"format", "source", "package", "toolchain", "builder_sha256", "artifact"}
            and manifest["format"] == FORMAT and HEX.fullmatch(manifest["builder_sha256"]))
    source = manifest["source"]
    require(isinstance(source, dict) and set(source) == {"commit", "inputs"}
            and re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["commit"]) and isinstance(source["inputs"], list) and source["inputs"])
    require(len(source["inputs"]) <= 4096 and len({entry.get("path") for entry in source["inputs"] if isinstance(entry, dict)}) == len(source["inputs"]))
    for entry in source["inputs"]:
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "size"}
                and isinstance(entry["path"], str) and not PurePosixPath(entry["path"]).is_absolute()
                and ".." not in PurePosixPath(entry["path"]).parts and "\\" not in entry["path"]
                and (entry["path"] in INPUTS or any(entry["path"].startswith(prefix + "/") for prefix in ["host/remote-control/src", "contracts"]))
                and HEX.fullmatch(entry["sha256"])
                and type(entry["size"]) is int and entry["size"] >= 0)
    artifact = manifest["artifact"]
    require(isinstance(artifact, dict) and set(artifact) == {"file", "sha256", "size", "files"}
            and re.fullmatch(r"ustc-dsh-remote-control-[0-9A-Za-z.-]+\.tgz", artifact["file"])
            and HEX.fullmatch(artifact["sha256"]) and digest(archive_raw) == artifact["sha256"]
            and type(artifact["size"]) is int and len(archive_raw) == artifact["size"])
    files, package = inspect_archive(archive_raw)
    require(manifest["package"] == {key: package[key] for key in ["name", "version", "dependencies", "peerDependencies", "type"]})
    require(artifact["file"] == "ustc-dsh-remote-control-" + package["version"] + ".tgz")
    require(isinstance(artifact["files"], list) and len(artifact["files"]) <= MAX_FILES)
    for entry in artifact["files"]:
        require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "size", "mode"}
                and type(entry["size"]) is int and type(entry["mode"]) is int)
    require(artifact["files"] == [file_record(name, files[name]) for name in sorted(files)])
    toolchain = manifest["toolchain"]
    require(isinstance(toolchain, dict) and set(toolchain) == {"node", "npm", "typescript", "dsh", "installed_dependencies", "platform", "architecture"}
            and isinstance(toolchain["dsh"], dict) and set(toolchain["dsh"]) == {"version", "entry_sha256"} and toolchain["dsh"].get("version") == DSH
            and HEX.fullmatch(toolchain["dsh"].get("entry_sha256", "")))
    require(isinstance(toolchain["node"], str) and re.fullmatch(r"v24\.[0-9]+\.[0-9]+", toolchain["node"])
            and int(toolchain["node"].split(".")[1]) >= 15
            and isinstance(toolchain["npm"], str) and VERSION.fullmatch(toolchain["npm"])
            and isinstance(toolchain["typescript"], str) and VERSION.fullmatch(toolchain["typescript"]))
    require(isinstance(toolchain["platform"], str) and re.fullmatch(r"[a-z0-9_]+", toolchain["platform"])
            and isinstance(toolchain["architecture"], str) and re.fullmatch(r"[A-Za-z0-9_]+", toolchain["architecture"]))
    require(toolchain["installed_dependencies"] == {**package["dependencies"], **package["peerDependencies"]})
    return manifest, files

def verify(directory, expected, unpack=None):
    private_directory(directory)
    manifest_raw = private_read(directory / "manifest.json", MAX_MANIFEST)
    # Authenticate the manifest before using even its archive filename.
    require(HEX.fullmatch(expected) and digest(manifest_raw) == expected)
    preliminary = parse_json(manifest_raw)
    filename = preliminary.get("artifact", {}).get("file", "")
    require(isinstance(filename, str) and re.fullmatch(r"ustc-dsh-remote-control-[0-9A-Za-z.-]+\.tgz", filename))
    archive_raw = private_read(directory / filename, MAX_ARCHIVE)
    manifest, files = validate(manifest_raw, archive_raw, expected)
    if unpack is not None:
        require(unpack.is_absolute() and unpack.parent.resolve() == unpack.parent and not unpack.exists() and not unpack.is_symlink())
        private_directory(unpack.parent)
        unpack.mkdir(mode=0o700)
        for name, content in files.items():
            target = unpack / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as destination:
                os.chmod(target, 0o600)
                destination.write(content)
    return {"manifest_sha256": expected, "artifact_sha256": manifest["artifact"]["sha256"],
            "source_commit": manifest["source"]["commit"], "file_count": len(files)}

def run(args, root, log=None, timeout=45):
    result = subprocess.run(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if log:
        with log.open("ab") as destination:
            destination.write(result.stdout); destination.write(result.stderr)
    require(result.returncode == 0)
    return result.stdout

def source_inputs(root):
    require(not run(["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored", "--", *INPUTS], root))
    names = run(["git", "ls-files", "-z", "--", *INPUTS], root).decode().split("\0")
    entries = []
    for name in sorted(filter(None, names)):
        path = root / name
        require(stat.S_ISREG(path.lstat().st_mode))
        raw = path.read_bytes()
        entries.append({"path": name, "sha256": digest(raw), "size": len(raw)})
    require(entries)
    return entries


def audit_imports(root, inputs, declared):
    sources = [entry["path"] for entry in inputs if entry["path"].startswith("host/remote-control/src/") and entry["path"].endswith(".ts")]
    require(sources)
    script = r"""const fs=require('node:fs'),path=require('node:path'),root=process.argv[1],ts=require(path.join(root,'node_modules/typescript'));
const sources=JSON.parse(process.argv[2]).map(name=>path.resolve(root,name)),owned=new Set(sources),declared=new Set(JSON.parse(process.argv[3]));
let invalid=false;
for(const source of sources){
 const file=ts.createSourceFile(source,fs.readFileSync(source,'utf8'),ts.ScriptTarget.Latest,true);
 const reference=value=>{
  if(!value||!ts.isStringLiteralLike(value)){invalid=true;return}
  const name=value.text;
  if(name.startsWith('node:'))return;
  if(name.startsWith('.')){
   const target=path.resolve(path.dirname(source),name.replace(/\.js$/,'.ts'));
   if(!owned.has(target)&&!owned.has(target.replace(/\.ts$/,'.d.ts')))invalid=true;
  }else{
   const parts=name.split('/'),pkg=name.startsWith('@')?parts.slice(0,2).join('/'):parts[0];
   if(!declared.has(pkg))invalid=true;
  }
 };
 const visit=node=>{
  if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier)reference(node.moduleSpecifier);
  if(ts.isImportTypeNode(node))reference(ts.isLiteralTypeNode(node.argument)?node.argument.literal:undefined);
  if(ts.isCallExpression(node)&&(node.expression.kind===ts.SyntaxKind.ImportKeyword||(ts.isIdentifier(node.expression)&&node.expression.text==='require')))reference(node.arguments[0]);
  ts.forEachChild(node,visit);
 };
 visit(file);
}
if(invalid)process.exit(1);
process.stdout.write(JSON.stringify({source_files:sources.length}));"""
    run(["node", "-e", script, str(root), json.dumps(sources), json.dumps(sorted(declared))], root)


def build(root, output, dsh):
    builder_hash = digest(Path(__file__).read_bytes())
    require(root.resolve() == root and output.is_absolute() and dsh.is_absolute() and dsh.is_file())
    local = root / ".local"
    local.mkdir(exist_ok=True, mode=0o700)
    require(local.resolve() == local and output.parent == local and not output.exists() and not output.is_symlink())
    inputs = source_inputs(root)
    commit = run(["git", "rev-parse", "HEAD"], root).decode().strip()
    package = parse_json((root / "host/remote-control/package.json").read_bytes())
    expected = {**package["dependencies"], **package["peerDependencies"]}
    audit_imports(root, inputs, expected)
    node = run(["node", "--version"], root).decode().strip()
    require(re.fullmatch(r"v24\.[0-9]+\.[0-9]+", node) and int(node.split(".")[1]) >= 15)
    dsh_hash = digest(dsh.read_bytes())
    dsh_version = run([str(dsh), "--version"], root, timeout=5).decode().strip()
    require(dsh_version == DSH)
    script = """const {createRequire}=require('node:module'),{readFileSync,existsSync}=require('node:fs'),{dirname,join}=require('node:path');
const req=createRequire(process.argv[1]),names=JSON.parse(process.argv[2]),result={};
for(const name of names){let path=dirname(req.resolve(name));for(;;){const file=join(path,'package.json');if(existsSync(file)){const pkg=JSON.parse(readFileSync(file));if(pkg.name===name){result[name]=pkg.version;break}}const next=dirname(path);if(next===path)throw Error('missing package');path=next}}
process.stdout.write(JSON.stringify(result));"""
    installed = parse_json(run(["node", "-e", script, str(root / "host/remote-control/package.json"), json.dumps(sorted(expected))], root))
    require(installed == expected)
    typescript = parse_json((root / "node_modules/typescript/package.json").read_bytes())["version"]
    require(typescript == parse_json((root / "package.json").read_bytes())["devDependencies"]["typescript"])
    output.mkdir(mode=0o700)
    log = output / "build.log"
    log.touch(mode=0o600)
    with tempfile.TemporaryDirectory(prefix=".build-", dir=output) as temporary:
        staged = Path(temporary) / "package"
        staged.mkdir(mode=0o700)
        (staged / "package.json").write_bytes((root / "host/remote-control/package.json").read_bytes())
        (staged / "README.md").write_bytes((root / "host/remote-control/README.md").read_bytes())
        run(["node", str(root / "node_modules/typescript/bin/tsc"), "--project", "host/remote-control/tsconfig.build.json",
             "--outDir", str(staged / "lib"), "--sourceRoot", "../src/"], root, log)
        packed = parse_json(run(["npm", "pack", ".", "--offline", "--ignore-scripts", "--json", "--pack-destination", str(output)], staged, log))
        if isinstance(packed, dict):
            require(set(packed) == {package["name"]})
            packed = [packed[package["name"]]]
        require(isinstance(packed, list) and len(packed) == 1)
        filename = packed[0]["filename"]
        require(re.fullmatch(r"ustc-dsh-remote-control-[0-9A-Za-z.-]+\.tgz", filename))
        artifact = output / filename
        artifact.chmod(0o600)
        raw = private_read(artifact, MAX_ARCHIVE)
        files, descriptor = inspect_archive(raw)
        # No stale generated file, new npm include rule or extra local asset may
        # silently enter the artifact, even if it has a superficially safe name.
        staged_files = {"package/" + path.relative_to(staged).as_posix(): path.read_bytes()
                        for path in staged.rglob("*") if path.is_file()}
        require(files == staged_files)
    require(digest(Path(__file__).read_bytes()) == builder_hash and digest(dsh.read_bytes()) == dsh_hash)
    require(source_inputs(root) == inputs and run(["git", "rev-parse", "HEAD"], root).decode().strip() == commit)
    manifest = {"format": FORMAT, "source": {"commit": commit, "inputs": inputs},
                "builder_sha256": builder_hash,
                "package": {key: descriptor[key] for key in ["name", "version", "dependencies", "peerDependencies", "type"]},
                "toolchain": {"node": node, "npm": run(["npm", "--version"], root).decode().strip(), "typescript": typescript,
                              "dsh": {"version": dsh_version, "entry_sha256": dsh_hash}, "installed_dependencies": installed,
                              "platform": sys.platform, "architecture": platform.machine()},
                "artifact": {"file": filename, "sha256": digest(raw), "size": len(raw),
                             "files": [file_record(name, files[name]) for name in sorted(files)]}}
    manifest_raw = json_bytes(manifest)
    with (output / "manifest.json").open("xb") as destination:
        os.chmod(destination.name, 0o600); destination.write(manifest_raw)
    return verify(output, digest(manifest_raw))

def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    builder = commands.add_parser("build")
    builder.add_argument("--output", type=Path, required=True)
    builder.add_argument("--dsh-bin", type=Path, required=True)
    checker = commands.add_parser("verify")
    checker.add_argument("--directory", type=Path, required=True)
    checker.add_argument("--expected-manifest-sha256", required=True)
    checker.add_argument("--unpack", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(Path(__file__).resolve().parents[2], args.output.absolute(), args.dsh_bin)
        else:
            result = verify(args.directory, args.expected_manifest_sha256, args.unpack)
        print(json.dumps(result, sort_keys=True))
    except (BundleError, OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, subprocess.SubprocessError):
        print("host bundle build/verification failed; no verified result was produced", file=sys.stderr)
        return 1
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

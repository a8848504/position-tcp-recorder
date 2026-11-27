#!/usr/bin/env python3
"""Build an offline Windows EXE, without shipping or installing Npcap."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import struct
import subprocess
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = re.search(r'const Current = "([0-9.]+)"', (ROOT / "internal/version/version.go").read_text()).group(1)
WIRESHARK = "4.6.9"
ARTIFACTS = {
    f"WiresharkPortable64_{WIRESHARK}.paf.exe": (
        f"https://2.na.dl.wireshark.org/win64/WiresharkPortable64_{WIRESHARK}.paf.exe",
        "71bcfda9eefec8088faaf0b8e6d026369ea83ae6149cd0b76ccf0b3194240db0",
    ),
    f"wireshark-{WIRESHARK}.tar.xz": (
        f"https://2.na.dl.wireshark.org/src/wireshark-{WIRESHARK}.tar.xz",
        "d062d416a1ab3a49975aafe3a671c882dde0562ccd71b078808ceb59d465fc0f",
    ),
    "etl2pcapng.exe": (
        "https://github.com/microsoft/etl2pcapng/releases/download/v1.11.0/etl2pcapng.exe",
        "c2d03aac43ea0f5626fc8d909e6688393feaf71bd6facd39aaf8a637382d9043",
    ),
    "etl2pcapng-LICENSE.txt": (
        "https://raw.githubusercontent.com/microsoft/etl2pcapng/v1.11.0/LICENSE",
        "9906940f61b1f0b533fa7d99baf55178b2808fbe113ea51dfbfad8572ccd5f2b",
    ),
    "etl2pcapng-v1.11.0.tar.gz": (
        "https://api.github.com/repos/microsoft/etl2pcapng/tarball/v1.11.0",
        "87144577c45cc89ca6d053ab68ac2f5b9f99cd381aa93ab9547632040744cfd1",
    ),
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def download(cache: Path, name: str) -> Path:
    url, expected = ARTIFACTS[name]
    target = cache / name
    if target.exists() and digest(target) == expected:
        return target
    print(f"Downloading {name}", flush=True)
    request = urllib.request.Request(url, headers={"User-Agent": "PositionTCP-build/1.0"})
    temp = target.with_name(name + ".part")
    with urllib.request.urlopen(request, timeout=120) as source, temp.open("wb") as output:
        shutil.copyfileobj(source, output)
    if digest(temp) != expected:
        temp.unlink()
        raise RuntimeError(f"SHA256 mismatch: {name}")
    temp.replace(target)
    return target


def pe_imports(path: Path) -> list[str]:
    """Read ordinary/delay PE imports to include all runtime DLL dependencies."""
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"Not a PE image: {path}")
    sections = struct.unpack_from("<H", data, pe + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe + 20)[0]
    optional = pe + 24
    is64 = struct.unpack_from("<H", data, optional)[0] == 0x20B
    directory = optional + (112 if is64 else 96)
    image_base = struct.unpack_from("<Q" if is64 else "<I", data, optional + (24 if is64 else 28))[0]
    section_base = optional + optional_size

    def file_offset(rva: int) -> int:
        for index in range(sections):
            start = section_base + index * 40
            virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from("<IIII", data, start + 8)
            if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
                return raw_pointer + rva - virtual_address
        return rva  # PE header RVAs.

    def string(rva: int) -> str:
        start = file_offset(rva)
        return data[start:data.index(0, start)].decode("ascii")

    result = []
    for directory_index, record_size, name_offset in ((1, 20, 12), (13, 32, 4)):
        rva, size = struct.unpack_from("<II", data, directory + directory_index * 8)
        if not rva:
            continue
        start = file_offset(rva)
        for offset in range(start, start + size, record_size):
            if not any(data[offset:offset + record_size]):
                break
            name_rva = struct.unpack_from("<I", data, offset + name_offset)[0]
            if directory_index == 13 and not (struct.unpack_from("<I", data, offset)[0] & 1):
                name_rva -= image_base
            if name_rva:
                result.append(string(name_rva))
    return result


def runtime_files(directory: Path) -> list[Path]:
    available = {p.name.casefold(): p for p in directory.iterdir() if p.is_file()}
    pending = ["tshark.exe", "dumpcap.exe", "mergecap.exe"]
    selected: dict[str, Path] = {}
    while pending:
        name = pending.pop().casefold()
        if name in selected:
            continue
        path = available[name]
        if name in {"wpcap.dll", "packet.dll", "npcaphelper.exe"}:
            raise RuntimeError("Npcap must not be redistributed in this package")
        selected[name] = path
        for dependency in pe_imports(path):
            key = dependency.casefold()
            if key in available and key not in selected:
                pending.append(key)
    selected["copying.txt"] = directory / "COPYING.txt"
    return sorted(selected.values())


def source_zip(destination: Path) -> None:
    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(ROOT.rglob("*")):
            relative = path.relative_to(ROOT)
            if not path.is_file() or any(part in {"build", "dist", "__pycache__", ".git"} for part in relative.parts):
                continue
            if path.suffix == ".syso" or path.name == "wireshark-runtime.zip":
                continue
            archive.write(path, "tcp-recorder/" + relative.as_posix())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default=shutil.which("go"))
    parser.add_argument("--sevenzip", default=shutil.which("7zz") or shutil.which("7z"))
    parser.add_argument("--cache", type=Path, default=ROOT / "build" / "cache")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    options = parser.parse_args()
    if not options.go:
        parser.error("Go SDK is required on the build machine only")
    cache = options.cache.resolve()
    cache.mkdir(parents=True, exist_ok=True)
    extracted = cache / "wireshark-windows"
    original = extracted / "App" / "Wireshark"
    portable = f"WiresharkPortable64_{WIRESHARK}.paf.exe"
    downloads = {name: download(cache, name) for name in ARTIFACTS if name != portable}
    if not (original / "tshark.exe").exists():
        if not options.sevenzip:
            parser.error("7-Zip/7zz is required to extract Wireshark Portable")
        downloads[portable] = download(cache, portable)
        subprocess.run([options.sevenzip, "x", "-y", "-o" + str(extracted), str(downloads[f"WiresharkPortable64_{WIRESHARK}.paf.exe"])], check=True)
    runtime_zip = ROOT / "internal" / "bundle" / "assets" / "wireshark-runtime.zip"
    selected = runtime_files(original)
    with zipfile.ZipFile(runtime_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in selected:
            archive.write(path, path.name)
        for name in ("etl2pcapng.exe", "etl2pcapng-LICENSE.txt"):
            archive.write(downloads[name], name)
    print(f"Embedded runtime: {len(selected)} Wireshark files, {runtime_zip.stat().st_size / 1024**2:.1f} MiB", flush=True)
    output = options.output.resolve() / f"PositionTCP-windows-x64-{VERSION}"
    output.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    environment["GOTOOLCHAIN"] = "local"
    subprocess.run([options.go, "run", "github.com/akavel/rsrc@v0.10.2", "-arch", "amd64", "-manifest", "cmd/tcp-recorder/app.manifest", "-o", "cmd/tcp-recorder/resource_windows_amd64.syso"], cwd=ROOT, env=environment, check=True)
    environment.update(GOOS="windows", GOARCH="amd64", CGO_ENABLED="0")
    executable = output / f"PositionTCP-Windows-amd64-{VERSION}.exe"
    subprocess.run([options.go, "build", "-trimpath", "-ldflags=-H=windowsgui -s -w", "-o", str(executable), "./cmd/tcp-recorder"], cwd=ROOT, env=environment, check=True)
    shutil.copyfile(ROOT / "README.md", output / "使用说明.md")
    for name in ("WINDOWS-VALIDATION.md", "VERIFICATION.md", "LICENSE", "THIRD-PARTY-NOTICES.md"):
        shutil.copyfile(ROOT / name, output / name)
    shutil.copyfile(original / "COPYING.txt", output / "Wireshark-COPYING.txt")
    shutil.copyfile(downloads["etl2pcapng-LICENSE.txt"], output / "etl2pcapng-LICENSE.txt")
    for name in (f"wireshark-{WIRESHARK}.tar.xz", "etl2pcapng-v1.11.0.tar.gz"):
        shutil.copyfile(downloads[name], output / name)
    source_zip(output / "工具源码.zip")
    manifest = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file() and path.name != "SHA256.json"}
    (output / "SHA256.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    archive_path = output.parent / (output.name + ".zip")
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(output.iterdir()):
            if path.is_file():
                archive.write(path, output.name + "/" + path.name)
    print(f"EXE: {executable}\nPackage: {archive_path}\nSHA256: {digest(archive_path)}", flush=True)


if __name__ == "__main__":
    main()

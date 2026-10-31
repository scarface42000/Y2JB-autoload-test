#!/usr/bin/env python3
"""Package the pinned PLK 1.1.0 runtime with the SKYBOZ theme."""
import argparse
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = [
    ("itsPLK/ps5-elfldr", "v0.27-b57d0e9", "elfldr-ps5-v0.27-b57d0e9.elf",
     "elfldr-ps5-v0.27-b57d0e9.elf", "116d023e9a6cb243d1d6c539b325bd0d140cc79de3afc3add5f34a98ccda4c93"),
    ("itsPLK/ps5-kexp", "v0.8-24cf6e5", "kexp-v0.8-24cf6e5.bin",
     "kexp-v0.8-24cf6e5.bin", "4e29cb74ffc1771b16e59d4998517aea32ecded651f814b71dc7ee50abff089f"),
    ("itsPLK/ps5-unified-autoloader", "v0.1.6-e7093cd", "ps5-unified-autoloader-v0.1.6-e7093cd.elf",
     "ps5-unified-autoloader.elf", "edc4f805404f80497026ba2d74f675ee7043b1ef7f4ed92b82c1ef200aac123d"),
]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(deps_dir, output, version):
    if not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        raise ValueError("Version must contain only letters, numbers, dots, dashes or underscores")
    deps_dir.mkdir(parents=True, exist_ok=True)
    files = {p.name: p.read_bytes() for p in (ROOT / "src").iterdir() if p.is_file()}
    for repo, tag, asset, target, digest in DEPENDENCIES:
        cached = deps_dir / asset
        if not cached.exists() or sha256(cached) != digest:
            temporary = cached.with_suffix(cached.suffix + ".part")
            subprocess.run(["curl", "--fail", "--location", "--retry", "3", "--output", str(temporary),
                            f"https://github.com/{repo}/releases/download/{tag}/{asset}"], check=True)
            if sha256(temporary) != digest:
                temporary.unlink()
                raise ValueError(f"SHA-256 mismatch: {asset}")
            temporary.replace(cached)
        files[target] = cached.read_bytes()

    substitutions = {
        "@@VERSION@@": version,
        "@@ELFLDR_FILE@@": DEPENDENCIES[0][3],
        "@@KEXP_FILE@@": DEPENDENCIES[1][3],
    }
    for name, data in list(files.items()):
        if name.endswith((".js", ".html", ".css")):
            text = data.decode("utf-8")
            for placeholder, value in substitutions.items():
                text = text.replace(placeholder, value)
            if re.search(r"@@[A-Z_]+@@", text):
                raise ValueError(f"Unresolved build placeholder in {name}")
            files[name] = text.encode("utf-8")

    output.mkdir(parents=True, exist_ok=True)
    cache = output / "download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY="
    if cache.exists():
        shutil.rmtree(cache)
    cache.mkdir(parents=True)
    for name, data in files.items():
        (cache / name).write_bytes(data)
    manifest = "\n".join(f"{name}|{len(data)}" for name, data in sorted(files.items()))
    package = output / "y2jb_update.zip"
    with zipfile.ZipFile(package, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
        archive.writestr("update-info.txt", manifest)
    (output / "y2jb_update.zip.sha256").write_text(f"{sha256(package)}  y2jb_update.zip\n")
    print(f"Built {package} ({len(files)} files); version {version}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deps-dir", type=Path, default=ROOT / ".deps")
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    parser.add_argument("--version", default="skyboz-1.1.0")
    args = parser.parse_args()
    build(args.deps_dir, args.output, args.version)

#!/usr/bin/env python3
"""Check the updater's manifest, required assets, and packaged JavaScript."""
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
import zipfile


def verify(package):
    with zipfile.ZipFile(package) as archive:
        assert archive.testzip() is None, "Corrupt ZIP entry"
        names = archive.namelist()
        assert len(names) == len(set(names)), "Duplicate ZIP entries"
        required = {"splash.html", "main.js", "global.js", "misc.js", "kernel.js", "lapse.js",
                    "relapse.js", "aioshellcode.js", "autoload.js", "update.js", "skyboz.css",
                    "icon0.png", "ps5-unified-autoloader.elf", "update-info.txt"}
        assert required <= set(names), "Missing runtime file"
        manifest = dict(line.rsplit("|", 1) for line in archive.read("update-info.txt").decode().splitlines())
        assert set(manifest) == set(names) - {"update-info.txt"}, "Incomplete manifest"
        for name, size in manifest.items():
            assert "/" not in name and "\\" not in name, "Unexpected package path"
            assert len(archive.read(name)) == int(size) > 0, f"Bad size: {name}"
        icon = archive.read("icon0.png")
        assert icon[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG"
        assert struct.unpack(">II", icon[16:24]) == (512, 512), "Expected 512x512 tile"
        for name in names:
            if name.endswith(".elf"):
                assert archive.read(name).startswith(b"\x7fELF"), f"Invalid ELF: {name}"
        assert "SKYBOZ LOADER" in archive.read("main.js").decode(), "Missing branding"
        assert "skyboz.css" in archive.read("splash.html").decode(), "Missing stylesheet link"
        with tempfile.TemporaryDirectory() as directory:
            for name in names:
                if name.endswith(".js"):
                    content = archive.read(name)
                    assert not re.search(rb"@@[A-Z_]+@@", content), f"Unresolved placeholder: {name}"
                    path = Path(directory) / name
                    path.write_bytes(content)
                    subprocess.run(["node", "--check", str(path)], check=True)
    print("Package verified: ZIP, complete manifest, tile, ELF headers, JS syntax, placeholders")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))

"""
Fails if the repository tracks compiled binaries or other large build output
(issue #5). Release assets are built from tags and attached to GitHub
Releases; they never belong in git.

usage: python3 tests/repo_hygiene.py      (exit status 0 = clean)
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Executable and archive formats, by magic bytes.
MAGIC = {
    b"\x7fELF": "ELF executable",
    b"MZ": "Windows executable",
    b"\xcf\xfa\xed\xfe": "Mach-O executable",
    b"\xfe\xed\xfa\xcf": "Mach-O executable",
    b"\xca\xfe\xba\xbe": "Mach-O universal binary",
}
# Tracked on purpose: the Gradle wrapper bootstrap jar.
ALLOWED = {"android/gradle/wrapper/gradle-wrapper.jar"}
MAX_BYTES = 1 << 20  # nothing hand-written in this repo comes close to 1 MiB


def problems():
    out = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    for path in filter(None, out.decode().split("\0")):
        if path in ALLOWED:
            continue
        full = os.path.join(ROOT, path)
        if not os.path.isfile(full):
            continue
        size = os.path.getsize(full)
        with open(full, "rb") as f:
            head = f.read(4)
        for magic, kind in MAGIC.items():
            if head.startswith(magic):
                yield f"{path}: {kind} ({size} bytes)"
                break
        else:
            if size > MAX_BYTES:
                yield f"{path}: {size} bytes, larger than {MAX_BYTES}"
            elif path.endswith((".aar", ".apk", ".so", ".exe", ".dylib")):
                yield f"{path}: build output"


def main():
    found = list(problems())
    for p in found:
        print("tracked binary:", p)
    if found:
        print("Remove them with `git rm --cached` and rely on .gitignore.")
        return 1
    print("repo hygiene: no tracked binaries")
    return 0


if __name__ == "__main__":
    sys.exit(main())

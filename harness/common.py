"""
Shared helpers for the New-GenADB evaluation harness: process management,
isolated adb environments, a test identity provider (IdP) issuing EdDSA JWTs.

This file is part of the immutable harness. Do not modify during Phase 2.
"""
import base64
import json
import os
import queue
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Proc:
    """A solution subprocess that emits JSON-lines events on stdout."""

    def __init__(self, args, cwd, name, env=None):
        self.name = name
        self.args = args
        self.events = []
        self.cv = threading.Condition()
        self.log_path = os.path.join(cwd, f"{name}.log")
        self.errf = open(self.log_path, "wb")
        self.p = subprocess.Popen(args, cwd=cwd, stdout=subprocess.PIPE, stderr=self.errf,
                                  stdin=subprocess.DEVNULL, env=env)
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            line = line.decode(errors="replace").strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                if not isinstance(ev, dict):
                    continue
            except ValueError:
                continue
            ev["_t"] = time.time()
            with self.cv:
                self.events.append(ev)
                self.cv.notify_all()
        with self.cv:
            self.cv.notify_all()

    def wait_event(self, names, timeout, after=0):
        """Wait for an event whose "event" field is in names. Returns event or None."""
        if isinstance(names, str):
            names = (names,)
        end = time.time() + timeout
        with self.cv:
            while True:
                for ev in self.events[after:]:
                    if ev.get("event") in names:
                        return ev
                rem = end - time.time()
                if rem <= 0 or (self.p.poll() is not None and not self._pending()):
                    for ev in self.events[after:]:
                        if ev.get("event") in names:
                            return ev
                    return None
                self.cv.wait(min(rem, 0.2))

    def _pending(self):
        return False

    def count(self):
        with self.cv:
            return len(self.events)

    def alive(self):
        return self.p.poll() is None

    def kill(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(3)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait(3)
        self.errf.close()


class AdbEnv:
    """An isolated adb host server (own HOME => own adbkey, own server port)."""

    def __init__(self, root):
        self.home = os.path.join(root, "adbhome")
        os.makedirs(self.home, exist_ok=True)
        self.port = free_port()
        self.env = dict(os.environ, HOME=self.home, ANDROID_ADB_SERVER_PORT=str(self.port),
                        ANDROID_SDK_HOME=self.home)
        self.env.pop("ADB_VENDOR_KEYS", None)
        self.run("start-server", timeout=20)
        self.pubkey = open(os.path.join(self.home, ".android", "adbkey.pub")).read()

    def run(self, *args, timeout=30, input=None):
        try:
            p = subprocess.run(["adb", *args], env=self.env, capture_output=True,
                               timeout=timeout, input=input)
            return p.returncode, p.stdout, p.stderr
        except subprocess.TimeoutExpired as e:
            return -9, e.stdout or b"", b"timeout"

    def popen(self, *args):
        return subprocess.Popen(["adb", *args], env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)

    def connect(self, addr, timeout=10):
        """adb connect + wait until state == device. Returns seconds taken or None."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            rc, out, err = self.run("connect", addr, timeout=max(1, timeout - (time.time() - t0)))
            if b"connected to" in out:
                st = self.wait_device(addr, timeout - (time.time() - t0))
                if st:
                    return time.time() - t0
            time.sleep(0.3)
        return None

    def wait_device(self, addr, timeout):
        end = time.time() + max(0.5, timeout)
        while time.time() < end:
            rc, out, err = self.run("-s", addr, "get-state", timeout=5)
            if out.strip() == b"device":
                return True
            time.sleep(0.2)
        return False

    def shell_ok(self, addr, timeout=5):
        rc, out, _ = self.run("-s", addr, "shell", "echo", "ping-ok", timeout=timeout)
        return rc == 0 and out.strip() == b"ping-ok"

    def close(self):
        self.run("kill-server", timeout=10)


class IdP:
    """Test identity provider / MDM signer: issues EdDSA JWTs."""

    def __init__(self, issuer="https://idp.genadb.test"):
        self.issuer = issuer
        self.key = Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw)

    def issue(self, sub, typ, aud, key=None, ttl=600, iat=None, signer=None, **extra):
        now = int(time.time()) if iat is None else iat
        claims = {"iss": self.issuer, "sub": sub, "aud": aud, "typ": typ, "iat": now,
                  "nbf": now - 5, "exp": now + ttl, "jti": uuid.uuid4().hex}
        if key:
            claims["cnf"] = {"key": key}
        claims.update(extra)
        header = {"alg": "EdDSA", "typ": "JWT"}
        signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode()) + "." +
                         b64u(json.dumps(claims, separators=(",", ":")).encode()))
        sig = (signer or self.key).sign(signing_input.encode())
        return signing_input + "." + b64u(sig)


def tmpdir(prefix):
    return tempfile.mkdtemp(prefix=f"genadb-{prefix}-")


def rmtree(path):
    shutil.rmtree(path, ignore_errors=True)


def listening_sockets(pid):
    """Return set of (ip, port) TCP LISTEN sockets owned by pid (Linux /proc)."""
    inodes = set()
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:["):
                inodes.add(link[8:-1])
    except OSError:
        return set()
    out = set()
    for fn, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            lines = open(fn).read().splitlines()[1:]
        except OSError:
            continue
        for ln in lines:
            parts = ln.split()
            if parts[3] != "0A" or parts[9] not in inodes:
                continue
            ip_hex, port_hex = parts[1].split(":")
            port = int(port_hex, 16)
            if v6:
                ip = "::" if int(ip_hex, 16) == 0 else ("::1" if ip_hex.endswith("01000000") and int(ip_hex[:24], 16) == 0 else ip_hex)
            else:
                b = bytes.fromhex(ip_hex)[::-1]
                ip = ".".join(str(x) for x in b)
            out.add((ip, port))
    return out

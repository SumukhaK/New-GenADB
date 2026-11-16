"""
Simulated Android device daemon (adbd) for the New-GenADB evaluation harness.

It speaks the real ADB wire protocol (CNXN / AUTH / STLS / OPEN / OKAY / WRTE /
CLSE) so that the *real* AOSP `adb` host binary can connect to it, exactly as it
would to a phone's adbd over TCP. It is NOT a phone: it implements only the
services the evaluation exercises (shell/exec, sync push/pull, package install
incl. split install sessions, logcat streaming, screencap, screenrecord stream,
JDWP echo) and records everything it receives so the harness can verify
integrity (hashes) end to end.

Two adbd security modes are emulated:
  * "tls"    - modern Wireless debugging: CNXN -> STLS -> TLS 1.3 with the host
               presenting its adbkey certificate; the key must be in
               `authorized_keys` (i.e. previously paired).
  * "legacy" - `adb tcpip 5555` style: AUTH token / RSA signature, plaintext.

This file is part of the immutable harness. Do not modify during Phase 2.
"""
import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time
import random

from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

A_SYNC = 0x434E5953
A_CNXN = 0x4E584E43
A_OPEN = 0x4E45504F
A_OKAY = 0x59414B4F
A_CLSE = 0x45534C43
A_WRTE = 0x45545257
A_AUTH = 0x48545541
A_STLS = 0x534C5453
A_VERSION = 0x01000001
A_STLS_VERSION = 0x01000000
MAX_PAYLOAD = 1024 * 1024
AUTH_TOKEN, AUTH_SIGNATURE, AUTH_RSAPUBLICKEY = 1, 2, 3

CMD_NAMES = {A_SYNC: "SYNC", A_CNXN: "CNXN", A_OPEN: "OPEN", A_OKAY: "OKAY",
             A_CLSE: "CLSE", A_WRTE: "WRTE", A_AUTH: "AUTH", A_STLS: "STLS"}


def parse_adb_pubkey(text):
    """Parse an adbkey.pub line (Android mincrypt RSA public key format)."""
    blob = base64.b64decode(text.strip().split()[0])
    nwords, = struct.unpack_from("<I", blob, 0)
    n = int.from_bytes(blob[8:8 + nwords * 4], "little")
    off = 8 + nwords * 4 * 2
    e, = struct.unpack_from("<I", blob, off)
    return rsa.RSAPublicNumbers(e, n).public_key()


class Conn:
    """Transport abstraction over a plain socket or a pyOpenSSL connection."""

    def __init__(self, sock):
        self.sock = sock
        self.tls = None
        self.wlock = threading.Lock()

    def recv_exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            try:
                chunk = (self.tls or self.sock).recv(n - len(buf))
            except Exception as e:  # OpenSSL errors / resets
                raise ConnectionError(str(e))
            if not chunk:
                raise ConnectionError("eof")
            buf += chunk
        return bytes(buf)

    def send(self, data):
        with self.wlock:
            if self.tls:
                self.tls.sendall(data)
            else:
                self.sock.sendall(data)


class FakeDevice:
    def __init__(self, mode="tls", authorized_keys=(), serial="GENADBTEST01",
                 canary="CANARY", logcat_rate=50, rng_seed=1,
                 auto_accept_new_keys=False, host="127.0.0.1", port=0):
        self.mode = mode
        self.authorized = [parse_adb_pubkey(k) for k in authorized_keys]
        self.serial = serial
        self.canary = canary
        self.logcat_rate = logcat_rate
        self.auto_accept = auto_accept_new_keys
        self.rng = random.Random(rng_seed)
        self.files = {}          # path -> bytes   (sync push target)
        self.installed = {}      # package hash -> bytes
        self.install_sessions = {}
        self.events = []         # (ts, kind, detail)
        self.connections = 0
        self.authed_connections = 0
        self.lock = threading.Lock()
        self.screencap_bytes = self._png(self.rng.randbytes(2 * 1024 * 1024 + 1234))
        self.logcat_seq = 0
        self.stop = threading.Event()
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((host, port))
        self.srv.listen(16)
        self.port = self.srv.getsockname()[1]
        self.live = set()
        if mode == "tls":
            self._make_tls_ctx()
        threading.Thread(target=self._accept_loop, daemon=True).start()

    # ------------------------------------------------------------------ utils
    @staticmethod
    def _png(body):
        return b"\x89PNG\r\n\x1a\n" + body

    def log(self, kind, detail=""):
        with self.lock:
            self.events.append((time.time(), kind, detail))

    def _make_tls_ctx(self):
        from OpenSSL import SSL, crypto
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "adbd")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(1)
                .not_valid_before(now - datetime.timedelta(days=1))
                .not_valid_after(now + datetime.timedelta(days=3650))
                .sign(key, hashes.SHA256()))
        ctx = SSL.Context(SSL.TLS_METHOD)
        ctx.set_min_proto_version(SSL.TLS1_3_VERSION)
        ctx.use_certificate(crypto.X509.from_cryptography(cert))
        ctx.use_privatekey(crypto.PKey.from_cryptography_key(key))
        authorized_nums = [k.public_numbers() for k in self.authorized]

        def verify(conn, x509obj, errnum, depth, ok):
            try:
                pub = x509obj.to_cryptography().public_key()
                return pub.public_numbers() in authorized_nums
            except Exception:
                return False
        ctx.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT, verify)
        self.tls_ctx = ctx

    def close(self):
        self.stop.set()
        try:
            self.srv.close()
        except Exception:
            pass
        for s in list(self.live):
            try:
                s.shutdown(socket.SHUT_RDWR)
                s.close()
            except Exception:
                pass

    def summary(self):
        return {"connections": self.connections,
                "authed_connections": self.authed_connections,
                "files": {k: hashlib.sha256(v).hexdigest() for k, v in self.files.items()},
                "installed": list(self.installed.keys())}

    # ---------------------------------------------------------------- protocol
    def _accept_loop(self):
        while not self.stop.is_set():
            try:
                s, _ = self.srv.accept()
            except OSError:
                return
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                self.connections += 1
            self.live.add(s)
            threading.Thread(target=self._serve, args=(s,), daemon=True).start()

    @staticmethod
    def pack(cmd, a0, a1, data=b""):
        return struct.pack("<6I", cmd, a0, a1, len(data), 0, cmd ^ 0xFFFFFFFF) + data

    def read_msg(self, c):
        hdr = c.recv_exact(24)
        cmd, a0, a1, ln, crc, magic = struct.unpack("<6I", hdr)
        if magic != cmd ^ 0xFFFFFFFF:
            raise ConnectionError("bad magic")
        if ln > MAX_PAYLOAD:
            raise ConnectionError("payload too large")
        data = c.recv_exact(ln) if ln else b""
        return cmd, a0, a1, data

    def banner(self):
        return ("device::ro.product.name=genadb_sim;ro.product.model=GenADB Simulated Phone;"
                "ro.product.device=genadbsim;features=cmd").encode()

    def _serve(self, sock):
        c = Conn(sock)
        try:
            cmd, a0, a1, data = self.read_msg(c)
            if cmd != A_CNXN:
                raise ConnectionError("expected CNXN")
            self.max_payload = min(a1, MAX_PAYLOAD) if a1 else 4096
            if self.mode == "tls":
                c.send(self.pack(A_STLS, A_STLS_VERSION, 0))
                cmd, a0, a1, data = self.read_msg(c)
                if cmd != A_STLS:
                    raise ConnectionError("expected STLS")
                from OpenSSL import SSL
                t = SSL.Connection(self.tls_ctx, sock)
                t.set_accept_state()
                t.do_handshake()
                c.tls = t
                self.log("tls_ok")
            else:
                token = os.urandom(20)
                c.send(self.pack(A_AUTH, AUTH_TOKEN, 0, token))
                ok = False
                while not ok:
                    cmd, a0, a1, data = self.read_msg(c)
                    if cmd != A_AUTH:
                        raise ConnectionError("expected AUTH")
                    if a0 == AUTH_SIGNATURE:
                        for k in self.authorized:
                            try:
                                k.verify(data, token, padding.PKCS1v15(),
                                         utils.Prehashed(hashes.SHA1()))
                                ok = True
                                break
                            except Exception:
                                pass
                        if not ok:
                            token = os.urandom(20)
                            c.send(self.pack(A_AUTH, AUTH_TOKEN, 0, token))
                    elif a0 == AUTH_RSAPUBLICKEY:
                        if self.auto_accept:
                            self.authorized.append(parse_adb_pubkey(data.rstrip(b"\0").decode()))
                            ok = True
                        else:
                            self.log("auth_rejected")
                            raise ConnectionError("unauthorized key")
            with self.lock:
                self.authed_connections += 1
            self.log("authed", self.mode)
            c.send(self.pack(A_CNXN, A_VERSION, MAX_PAYLOAD, self.banner()))
            self._stream_loop(c)
        except Exception as e:
            self.log("conn_end", repr(e)[:200])
        finally:
            self.live.discard(sock)
            try:
                sock.close()
            except Exception:
                pass

    def _stream_loop(self, c):
        streams = {}
        next_id = [1]
        slock = threading.Lock()

        while True:
            cmd, a0, a1, data = self.read_msg(c)
            if cmd == A_OPEN:
                remote = a0
                local = next_id[0]
                next_id[0] += 1
                name = data.rstrip(b"\0").decode(errors="replace")
                st = Stream(self, c, local, remote, name)
                with slock:
                    streams[local] = st
                c.send(self.pack(A_OKAY, local, remote))
                threading.Thread(target=st.run, daemon=True).start()
            elif cmd == A_WRTE:
                st = streams.get(a1)
                if st is None:
                    c.send(self.pack(A_CLSE, 0, a0))
                    continue
                st.inbox_put(data)
                c.send(self.pack(A_OKAY, a1, a0))
            elif cmd == A_OKAY:
                st = streams.get(a1)
                if st:
                    st.okay.release()
            elif cmd == A_CLSE:
                st = streams.pop(a1, None)
                if st:
                    st.remote_closed()
            elif cmd == A_CNXN:
                raise ConnectionError("re-CNXN")


class Stream:
    def __init__(self, dev, conn, local, remote, name):
        self.dev, self.c, self.local, self.remote, self.name = dev, conn, local, remote, name
        self.okay = threading.Semaphore(1)
        self.inbuf = bytearray()
        self.cv = threading.Condition()
        self.closed_in = False
        self.closed = False

    # data from host
    def inbox_put(self, data):
        with self.cv:
            self.inbuf += data
            self.cv.notify_all()

    def remote_closed(self):
        with self.cv:
            self.closed_in = True
            self.closed = True
            self.cv.notify_all()
        self.okay.release()

    def read(self, n):
        with self.cv:
            while len(self.inbuf) < n and not self.closed_in:
                self.cv.wait(1)
            if len(self.inbuf) < n:
                raise ConnectionError("stream closed")
            out = bytes(self.inbuf[:n])
            del self.inbuf[:n]
            return out

    def read_all_until(self, total):
        return self.read(total)

    # data to host
    def write(self, data):
        mp = self.dev.max_payload
        for i in range(0, len(data), mp):
            if self.closed:
                raise ConnectionError("closed")
            if not self.okay.acquire(timeout=30):
                raise ConnectionError("okay timeout")
            if self.closed:
                raise ConnectionError("closed")
            self.c.send(FakeDevice.pack(A_WRTE, self.local, self.remote, data[i:i + mp]))

    def close(self):
        if not self.closed:
            self.closed = True
            try:
                self.c.send(FakeDevice.pack(A_CLSE, self.local, self.remote))
            except Exception:
                pass

    # service dispatch
    def run(self):
        d = self.dev
        name = self.name
        d.log("open", name[:120])
        try:
            if name.startswith("sync:"):
                self.sync()
            elif name.startswith("jdwp:"):
                self.jdwp()
            elif name.startswith("shell") or name.startswith("exec:"):
                cmd = name.split(":", 1)[1]
                self.shell(cmd)
            elif name.startswith("reboot"):
                self.write(b"")
            else:
                d.log("unknown_service", name)
        except Exception as e:
            d.log("stream_err", f"{name[:60]}: {e!r}"[:200])
        finally:
            self.close()

    def shell(self, cmd):
        d = self.dev
        c = cmd.strip()
        if "logcat" in c:
            self.logcat()
        elif c.startswith("echo "):
            self.write((c[5:].strip("'\"") + "\n").encode())
        elif c.startswith("getprop"):
            props = {"ro.serialno": d.serial, "ro.product.model": "GenADB Simulated Phone",
                     "ro.build.version.sdk": "35", "ro.build.version.release": "15",
                     "genadb.canary": d.canary}
            parts = c.split()
            if len(parts) > 1:
                self.write((props.get(parts[1], "") + "\n").encode())
            else:
                self.write("".join(f"[{k}]: [{v}]\n" for k, v in props.items()).encode())
        elif c.startswith("cat-canary"):
            self.write((d.canary + "\n").encode())
        elif c.startswith("screencap"):
            self.write(d.screencap_bytes)
        elif c.startswith("screenrecord"):
            self.screenrecord(c)
        elif "package" in c and "install-create" in c:
            sid = str(len(d.install_sessions) + 1000)
            d.install_sessions[sid] = []
            self.write(f"Success: created install session [{sid}]\n".encode())
        elif "package" in c and "install-write" in c:
            parts = c.replace("'", "").split()
            size = int(parts[parts.index("-S") + 1])
            sid = parts[parts.index("-S") + 2]
            blob = self.read(size)
            d.install_sessions.setdefault(sid, []).append(blob)
            self.write(f"Success: streamed {size} bytes\n".encode())
        elif "package" in c and "install-commit" in c:
            sid = c.replace("'", "").split()[-1]
            blobs = d.install_sessions.pop(sid, [])
            h = hashlib.sha256(b"".join(hashlib.sha256(b).digest() for b in blobs)).hexdigest()
            d.installed[h] = len(blobs)
            d.log("install_multi", h)
            self.write(b"Success\n")
        elif "package" in c and "install" in c and "-S" in c:
            parts = c.replace("'", "").split()
            size = int(parts[parts.index("-S") + 1])
            blob = self.read(size)
            h = hashlib.sha256(blob).hexdigest()
            d.installed[h] = 1
            d.log("install", h)
            self.write(b"Success\n")
        elif c.startswith("pm ") or c.startswith("am "):
            self.write(b"Success\n")
        else:
            self.write(b"")

    def _produce(self, gen):
        """Like real adbd: a producer fills a pipe; after each OKAY the daemon
        sends everything accumulated so far (up to max payload) in one WRTE."""
        buf = bytearray()
        cv = threading.Condition()
        done = [False]

        def producer():
            try:
                for chunk in gen():
                    if self.closed:
                        break
                    with cv:
                        buf.extend(chunk)
                        cv.notify()
            finally:
                with cv:
                    done[0] = True
                    cv.notify()
        threading.Thread(target=producer, daemon=True).start()
        mp = self.dev.max_payload
        while not self.closed:
            if not self.okay.acquire(timeout=30):
                raise ConnectionError("okay timeout")
            with cv:
                while not buf and not done[0]:
                    cv.wait(0.5)
                if not buf and done[0]:
                    self.okay.release()
                    return
                out = bytes(buf[:mp])
                del buf[:mp]
            if self.closed:
                return
            self.c.send(FakeDevice.pack(A_WRTE, self.local, self.remote, out))

    def logcat(self):
        d = self.dev
        interval = 1.0 / max(1, d.logcat_rate)

        def gen():
            nxt = time.time()
            while not self.closed:
                with d.lock:
                    d.logcat_seq += 1
                    seq = d.logcat_seq
                ts = time.time()
                yield (f"11-16 12:00:00.000  4242  4242 I GenADBSim: seq={seq} ts={ts:.6f} "
                       f"payload={'x' * 60}\n").encode()
                nxt += interval
                time.sleep(max(0.0, nxt - time.time()))
        self._produce(gen)

    def screenrecord(self, c):
        # ~3s of pseudo h264 at ~4 Mbit/s in 16KiB frames carrying timestamps
        d = self.dev

        def gen():
            end = time.time() + 3.0
            n = 0
            nxt = time.time()
            while time.time() < end and not self.closed:
                hdr = f"H264FRAME {n} {time.time():.6f}\n".encode().ljust(64, b" ")
                yield hdr + d.rng.randbytes(16 * 1024 - 64)
                n += 1
                nxt += 16 * 1024 * 8 / 4_000_000
                time.sleep(max(0.0, nxt - time.time()))
        self._produce(gen)

    def jdwp(self):
        hs = self.read(14)
        if hs != b"JDWP-Handshake":
            return
        self.write(b"JDWP-Handshake")
        while True:
            hdr = self.read(11)
            ln = struct.unpack(">I", hdr[:4])[0]
            body = self.read(ln - 11) if ln > 11 else b""
            pid = hdr[4:8]
            reply = struct.pack(">I", 11 + len(body)) + pid + b"\x80\x00\x00" + body
            self.write(reply)

    def sync(self):
        d = self.dev
        while True:
            hdr = self.read(8)
            sid, ln = hdr[:4], struct.unpack("<I", hdr[4:])[0]
            if sid == b"QUIT":
                return
            arg = self.read(ln) if ln else b""
            if sid == b"STAT":
                p = arg.decode()
                if p in d.files:
                    self.write(b"STAT" + struct.pack("<III", 0o100644, len(d.files[p]), int(time.time())))
                elif p.endswith("/") or p in ("/sdcard", "/data/local/tmp", "/sdcard/Download"):
                    self.write(b"STAT" + struct.pack("<III", 0o040755, 4096, int(time.time())))
                else:
                    self.write(b"STAT" + struct.pack("<III", 0, 0, 0))
            elif sid == b"SEND":
                p = arg.decode().rsplit(",", 1)[0]
                buf = bytearray()
                while True:
                    h2 = self.read(8)
                    t, l2 = h2[:4], struct.unpack("<I", h2[4:])[0]
                    if t == b"DATA":
                        buf += self.read(l2)
                    elif t == b"DONE":
                        break
                    else:
                        raise ConnectionError("bad sync chunk")
                d.files[p] = bytes(buf)
                d.log("push", f"{p} {hashlib.sha256(buf).hexdigest()}")
                self.write(b"OKAY" + struct.pack("<I", 0))
            elif sid == b"RECV":
                p = arg.decode()
                data = d.files.get(p)
                if data is None:
                    msg = b"No such file"
                    self.write(b"FAIL" + struct.pack("<I", len(msg)) + msg)
                    continue
                out = bytearray()
                for i in range(0, len(data), 64 * 1024):
                    ch = data[i:i + 64 * 1024]
                    out += b"DATA" + struct.pack("<I", len(ch)) + ch
                    if len(out) >= 512 * 1024:
                        self.write(bytes(out))
                        out = bytearray()
                out += b"DONE" + struct.pack("<I", 0)
                self.write(bytes(out))
            elif sid == b"LIST":
                self.write(b"DONE" + struct.pack("<IIII", 0, 0, 0, 0))
            else:
                raise ConnectionError(f"unknown sync {sid!r}")


if __name__ == "__main__":
    import sys
    keys = []
    if len(sys.argv) > 2:
        keys = [open(sys.argv[2]).read()]
    dev = FakeDevice(mode=sys.argv[1] if len(sys.argv) > 1 else "tls", authorized_keys=keys, port=0)
    print(json.dumps({"port": dev.port}), flush=True)
    while True:
        time.sleep(1)

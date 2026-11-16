"""
Re-runs the full (locked) eval.py scenario suite with the relay reached over
alternative transports, without modifying eval.py:

  ws         WebSocket (ws://) relay listener
  wss        WebSocket over TLS (wss://) with a private CA (--relay-ca)
  wss-proxy  wss:// through a strict HTTP CONNECT proxy (only CONNECT allowed,
             everything else answered 403), as in locked-down corporate egress

A small wrapper rewrites the CLI arguments eval.py passes to `genadb`
(relay --listen -> --ws-listen, agents --relay host:port -> wss://...).
Exit status 0 iff every transport scores within 1.0 of the raw-TCP score
and no security check (C.*, T.tamper_never_silent, S.no_plaintext_on_wire)
regresses.

usage: python tests/transport_e2e.py [ws wss wss-proxy]
"""
import datetime
import ipaddress
import os
import socket
import stat
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import eval as ev  # noqa: E402
from solution import run_solution  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

SECURITY = [k for k in ev.WEIGHTS if k.startswith("C.")] + ["T.tamper_never_silent", "S.no_plaintext_on_wire"]


def make_cert(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "genadb-test-relay")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(d, "relay.crt"), os.path.join(d, "relay.key")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    return cp, kp


class ConnectProxy:
    """Strict HTTP proxy: only CONNECT is allowed; plain requests get 403."""

    def __init__(self):
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.connects = 0
        self.rejected = 0
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        buf = b""
        while b"\r\n\r\n" not in buf:
            ch = c.recv(4096)
            if not ch:
                c.close()
                return
            buf += ch
        line = buf.split(b"\r\n", 1)[0].decode()
        parts = line.split()
        if len(parts) < 2 or parts[0] != "CONNECT":
            self.rejected += 1
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            c.close()
            return
        host, port = parts[1].rsplit(":", 1)
        try:
            u = socket.create_connection((host, int(port)), timeout=5)
        except OSError:
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            c.close()
            return
        self.connects += 1
        c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        rest = buf.split(b"\r\n\r\n", 1)[1]
        if rest:
            u.sendall(rest)

        def pump(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        threading.Thread(target=pump, args=(c, u), daemon=True).start()
        threading.Thread(target=pump, args=(u, c), daemon=True).start()


def make_wrapper(d, binary, mode, cert, key, proxy_port):
    w = os.path.join(d, f"genadb-{mode}")
    tls = mode.startswith("wss")
    scheme = "wss" if tls else "ws"
    host = "localhost" if tls else "127.0.0.1"
    src = f'''#!{sys.executable}
import os, socket, sys
args = sys.argv[1:]
out = []
i = 0
sub = args[0] if args else ""
while i < len(args):
    a = args[i]
    if sub == "relay" and a == "--listen":
        s = socket.socket(); s.bind(("127.0.0.1", 0)); raw = s.getsockname()[1]; s.close()
        out += ["--listen", "127.0.0.1:%d" % raw, "--ws-listen", args[i + 1]]
        if {tls!r}:
            out += ["--tls-cert", {cert!r}, "--tls-key", {key!r}]
        i += 2
        continue
    if sub in ("device", "connect") and a == "--relay":
        port = args[i + 1].rsplit(":", 1)[1]
        out += ["--relay", "{scheme}://{host}:%s/" % port]
        if {tls!r}:
            out += ["--relay-ca", {cert!r}]
        if {proxy_port!r}:
            out += ["--proxy", "http://127.0.0.1:{proxy_port}"]
        i += 2
        continue
    out.append(a)
    i += 1
os.execv({binary!r}, [{binary!r}] + out)
'''
    open(w, "w").write(src)
    os.chmod(w, os.stat(w).st_mode | stat.S_IEXEC)
    return w


def score(R):
    return sum(w * ev.clamp(float(R.get(k, 0.0))) for k, w in ev.WEIGHTS.items())


def main(modes):
    binary = run_solution()["binary"]
    d = tempfile.mkdtemp(prefix="genadb-transport-")
    cert, key = make_cert(d)
    os.environ["NO_PROXY"] = ""
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"):
        os.environ.pop(k, None)
    R0, _ = ev.run_all(binary)
    base = score(R0)
    print(f"raw-tcp      score={base:.2f}")
    ok = True
    for mode in modes:
        proxy = ConnectProxy() if mode == "wss-proxy" else None
        w = make_wrapper(d, binary, mode, cert, key, proxy.port if proxy else 0)
        ev.LOG.clear()
        R, errors = ev.run_all(w)
        s = score(R)
        regress = [k for k in SECURITY if R.get(k, 0) < R0.get(k, 0)]
        low = [f"{k}={R.get(k, 0):.2f}" for k in ev.WEIGHTS if R.get(k, 0) < 0.999]
        extra = f" proxy_connects={proxy.connects} proxy_rejected={proxy.rejected}" if proxy else ""
        print(f"{mode:12s} score={s:.2f} below1={low} security_regressions={regress}{extra}")
        for e in errors:
            print("  ERROR", e)
        if s < base - 1.0 or regress or (proxy and proxy.connects == 0):
            ok = False
            for line in ev.LOG:
                print("  NOTE", line)
    print("TRANSPORT_E2E:", "PASS" if ok else "FAIL")
    sys.stdout.flush()
    os._exit(0 if ok else 1)


if __name__ == "__main__":
    main(sys.argv[1:] or ["ws", "wss", "wss-proxy"])

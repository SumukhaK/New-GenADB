"""
New-GenADB evaluation harness (immutable during Phase 2).

Builds the solution (via solution.run_solution()), then drives the `genadb`
binary through five independent scenarios that run in parallel, each with its
own relay, simulated phone (harness/fake_adbd.py), network simulator
(harness/netsim.py) and an isolated *real* AOSP adb host server:

  S  solo / legacy adbd   functional deploy+debug surface, reconnect, perf,
                          confidentiality on the wire
  W  solo pairing abuse   wrong codes, burn-after-3, fresh code
  T  solo integrity       bit-flip tampering, connection drop, outage recovery
  C  corporate / TLS adbd identity, authorization, policy, revoke, audit
  L  solo LAN path        direct path latency when a LAN route exists

Every check yields a fraction in [0,1]; weights sum to 100. Higher SCORE is
better. Prints a per-check breakdown, then `SCORE: <float>`.
See remote_adb_research_findings.md section 16 for the specification.
"""
import hashlib
import json
import math
import os
import random
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "harness"))

from fake_adbd import FakeDevice  # noqa: E402
from netsim import Proxy  # noqa: E402
from common import Proc, AdbEnv, IdP, tmpdir, rmtree, free_port, listening_sockets, b64u  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

TIME_LIMIT_SECONDS = 180

WEIGHTS = {
    # --- S: solo functional surface (28)
    "S.pair_and_connect": 3, "S.shell": 2, "S.push_pull_integrity": 5, "S.install_apk": 4,
    "S.install_multiple_aab_path": 3, "S.screencap": 3, "S.logcat_stream": 3,
    "S.screenrecord_stream": 2, "S.jdwp_debugger": 2, "S.reconnect_without_code": 1,
    # --- S/W: solo security (14)
    "S.no_plaintext_on_wire": 4, "S.pairing_code_not_on_wire": 2, "S.ciphertext_incompressible": 1,
    "W.wrong_code_rejected": 2, "W.burn_after_3_failures": 4, "W.fresh_code_works": 1,
    # --- T: integrity & resilience (18)
    "T.tamper_never_silent": 8, "T.push_survives_drop": 5, "T.outage_recovery": 5,
    # --- C: corporate (30)
    "C.authorized_session": 6,
    "C.deny_unauthorized_user": 2, "C.deny_expired": 2, "C.deny_forged": 2, "C.deny_wrong_audience": 2,
    "C.deny_stolen_token": 2, "C.deny_no_identity": 2,
    "C.debugging_disallowed": 3, "C.revoke_kills_session": 2, "C.revoke_blocks_new": 2,
    "C.audit_log": 3, "C.loopback_and_lazy_adbd": 2,
    # --- performance (7) + LAN (3)
    "P.push_throughput": 3, "P.time_to_ready": 2, "P.logcat_latency": 2,
    "L.lan_direct_latency": 3,
}
assert abs(sum(WEIGHTS.values()) - 100) < 1e-9

LOG = []
LOG_LOCK = threading.Lock()


def note(msg):
    with LOG_LOCK:
        LOG.append(msg)


def clamp(x):
    return max(0.0, min(1.0, x))


# ----------------------------------------------------------------- utilities
class World:
    """Relay + proxies + phone + adb host for one scenario."""

    def __init__(self, binary, name, mode="solo", adbd_mode="legacy", leg_delay_ms=10.0,
                 rate_mbit=200.0, policy=None, audit=False, admin=False):
        self.binary, self.name, self.mode = binary, name, mode
        self.root = tmpdir(name)
        self.procs = []
        self.adb = AdbEnv(self.root)
        self.canary = "GENADB-CANARY-" + os.urandom(8).hex()
        self.phone = FakeDevice(mode=adbd_mode, authorized_keys=[self.adb.pubkey],
                                canary=self.canary, rng_seed=random.randrange(1 << 30))
        self.relay_port = free_port()
        self.dev_leg = Proxy(("127.0.0.1", self.relay_port), leg_delay_ms, rate_mbit, f"{name}-devleg")
        self.phone_leg = Proxy(("127.0.0.1", self.relay_port), leg_delay_ms, rate_mbit, f"{name}-phoneleg")
        args = [binary, "relay", "--listen", f"127.0.0.1:{self.relay_port}", "--mode", mode]
        self.policy_path = None
        if policy is not None:
            self.policy_path = os.path.join(self.root, "policy.json")
            with open(self.policy_path, "w") as f:
                json.dump(policy, f)
            args += ["--policy", self.policy_path]
        self.audit_path = None
        if audit:
            self.audit_path = os.path.join(self.root, "audit.jsonl")
            args += ["--audit", self.audit_path]
        self.admin_addr = None
        if admin:
            self.admin_addr = f"127.0.0.1:{free_port()}"
            self.admin_token = os.urandom(16).hex()
            args += ["--admin", self.admin_addr, "--admin-token", self.admin_token]
        self.relay = self.spawn(args, "relay")
        if not self.relay.wait_event("ready", 15):
            raise RuntimeError("relay did not become ready")

    def spawn(self, args, name):
        p = Proc(args, self.root, f"{name}-{len(self.procs)}")
        self.procs.append(p)
        return p

    def state(self, who):
        d = os.path.join(self.root, "state-" + who)
        os.makedirs(d, exist_ok=True)
        return d

    def keygen(self, who):
        p = subprocess.run([self.binary, "keygen", "--state", self.state(who)], capture_output=True, timeout=20)
        for line in p.stdout.decode().splitlines():
            try:
                ev = json.loads(line)
                if ev.get("event") == "pubkey":
                    return ev["pubkey"]
            except ValueError:
                pass
        raise RuntimeError("keygen failed: " + p.stderr.decode()[-300:])

    def device(self, who="phone", phone=None, extra=()):
        phone = phone or self.phone
        args = [self.binary, "device", "--relay", self.phone_leg.addr, "--adbd", f"127.0.0.1:{phone.port}",
                "--state", self.state(who), "--mode", self.mode, *extra]
        return self.spawn(args, "device-" + who)

    def connect(self, who="desk", extra=()):
        args = [self.binary, "connect", "--relay", self.dev_leg.addr, "--state", self.state(who),
                "--listen", "127.0.0.1:0", "--mode", self.mode, *extra]
        return self.spawn(args, "connect-" + who)

    def captured(self):
        return self.dev_leg.captured() + self.phone_leg.captured()

    def close(self):
        for p in self.procs:
            try:
                p.kill()
            except Exception:
                pass
        for x in (self.dev_leg, self.phone_leg, self.phone):
            try:
                x.close()
            except Exception:
                pass
        try:
            self.adb.close()
        except Exception:
            pass
        rmtree(self.root)


def wait_listening(proc, timeout=15):
    ev = proc.wait_event(("listening", "error"), timeout)
    if ev and ev.get("event") == "listening":
        return ev["addr"]
    return None


def adb_bytes(world, serial, *args, timeout=30):
    rc, out, err = world.adb.run("-s", serial, *args, timeout=timeout)
    return rc, out, err


def push_and_time(world, serial, data, remote, timeout=60):
    path = os.path.join(world.root, "push-" + os.urandom(4).hex())
    with open(path, "wb") as f:
        f.write(data)
    t0 = time.time()
    rc, out, err = world.adb.run("-s", serial, "push", path, remote, timeout=timeout)
    dt = time.time() - t0
    ok = rc == 0 and world.phone.files.get(remote) == data
    return ok, dt, rc


def jdwp_rtts(world, serial, n=30):
    lp = free_port()
    rc, _, _ = world.adb.run("-s", serial, "forward", f"tcp:{lp}", "jdwp:4242", timeout=10)
    if rc != 0:
        return None
    try:
        s = socket.create_connection(("127.0.0.1", lp), timeout=10)
        s.settimeout(10)
        s.sendall(b"JDWP-Handshake")
        hs = b""
        while len(hs) < 14:
            ch = s.recv(14 - len(hs))
            if not ch:
                return None
            hs += ch
        if hs != b"JDWP-Handshake":
            return None
        rtts = []
        for i in range(n):
            body = os.urandom(16)
            pkt = struct.pack(">IIBBB", 11 + len(body), i + 1, 0, 1, 1) + body
            t0 = time.time()
            s.sendall(pkt)
            buf = b""
            while len(buf) < len(pkt):
                ch = s.recv(65536)
                if not ch:
                    return None
                buf += ch
            if buf[11:] != body:
                return None
            rtts.append((time.time() - t0) * 1000)
        s.close()
        return rtts
    except OSError:
        return None
    finally:
        world.adb.run("-s", serial, "forward", "--remove", f"tcp:{lp}", timeout=5)


def logcat_sample(world, serial, seconds=3.0):
    p = world.adb.popen("-s", serial, "logcat")
    lat, seqs = [], []
    end = time.time() + seconds
    buf = b""
    try:
        os.set_blocking(p.stdout.fileno(), False)
        while time.time() < end:
            try:
                ch = p.stdout.read(65536)
            except (BlockingIOError, TypeError):
                ch = None
            if not ch:
                time.sleep(0.005)
                continue
            now = time.time()
            buf += ch
            *lines, buf = buf.split(b"\n")
            for ln in lines:
                m = re.search(rb"seq=(\d+) ts=([\d.]+)", ln)
                if m:
                    seqs.append(int(m.group(1)))
                    lat.append((now - float(m.group(2))) * 1000)
    finally:
        p.kill()
        p.wait()
    return seqs, lat


def median(xs):
    xs = sorted(xs)
    return xs[len(xs) // 2] if xs else None


def denied(world, proc, phone, timeout=12):
    """True if a connect attempt never yields a usable adb device and never reaches adbd."""
    before = phone.connections
    addr = wait_listening(proc, timeout)
    if addr:
        t = world.adb.connect(addr, timeout=4)
        if t is not None and world.adb.shell_ok(addr, 3):
            return False
        world.adb.run("disconnect", addr, timeout=5)
    proc.kill()
    return phone.connections == before


# ---------------------------------------------------------------- scenarios
def scenario_S(binary, R):
    w = World(binary, "S", leg_delay_ms=20.0, rate_mbit=200.0)
    try:
        dev = w.device()
        code_ev = dev.wait_event("pairing_code", 15)
        if not code_ev:
            note("S: no pairing_code event")
            return
        code = str(code_ev["code"])
        t0 = time.time()
        con = w.connect(extra=["--code", code])
        addr = wait_listening(con, 20)
        if not addr:
            note("S: connect never listened")
            return
        t_conn = w.adb.connect(addr, timeout=15)
        if t_conn is None:
            note("S: adb connect failed")
            return
        ttr = time.time() - t0
        R["S.pair_and_connect"] = 1.0
        R["P.time_to_ready"] = clamp((10.0 - ttr) / 9.0)
        note(f"S: time_to_ready={ttr:.2f}s")
        serial = addr
        rc, out, _ = adb_bytes(w, serial, "shell", "echo", "hello-genadb")
        rc2, out2, _ = adb_bytes(w, serial, "shell", "cat-canary")
        R["S.shell"] = 1.0 if (out.strip() == b"hello-genadb" and out2.strip() == w.canary.encode()) else 0.0

        data = os.urandom(8 * 1024 * 1024)
        ok, dt, rc = push_and_time(w, serial, data, "/sdcard/big.bin", timeout=60)
        pull_path = os.path.join(w.root, "pulled.bin")
        rcp, _, _ = adb_bytes(w, serial, "pull", "/sdcard/big.bin", pull_path, timeout=60)
        pulled_ok = rcp == 0 and os.path.exists(pull_path) and open(pull_path, "rb").read() == data
        R["S.push_pull_integrity"] = (0.5 if ok else 0) + (0.5 if pulled_ok else 0)
        if ok:
            mbps = len(data) / dt / 1e6
            note(f"S: push throughput={mbps:.2f} MB/s ({dt:.2f}s)")
            R["P.push_throughput"] = clamp(math.log(max(mbps, 1e-9) / 0.5) / math.log(60 / 0.5))

        apk = os.urandom(3 * 1024 * 1024 + 17)
        apk_path = os.path.join(w.root, "app-debug.apk")
        open(apk_path, "wb").write(apk)
        rc, out, _ = adb_bytes(w, serial, "install", apk_path, timeout=60)
        R["S.install_apk"] = 1.0 if (rc == 0 and hashlib.sha256(apk).hexdigest() in w.phone.installed) else 0.0

        splits = [os.urandom(700 * 1024 + i) for i in range(3)]
        sp = []
        for i, b in enumerate(splits):
            p = os.path.join(w.root, f"split_{i}.apk")
            open(p, "wb").write(b)
            sp.append(p)
        rc, out, _ = adb_bytes(w, serial, "install-multiple", *sp, timeout=60)
        h = hashlib.sha256(b"".join(hashlib.sha256(b).digest() for b in splits)).hexdigest()
        R["S.install_multiple_aab_path"] = 1.0 if (rc == 0 and h in w.phone.installed) else 0.0

        rc, out, _ = adb_bytes(w, serial, "exec-out", "screencap", "-p", timeout=60)
        R["S.screencap"] = 1.0 if out == w.phone.screencap_bytes else 0.0

        seqs, lat = logcat_sample(w, serial, 3.0)
        if seqs:
            contiguous = all(b == a + 1 for a, b in zip(seqs, seqs[1:]))
            R["S.logcat_stream"] = clamp(len(seqs) / 100.0) * (1.0 if contiguous else 0.5)
            ml = median(lat)
            note(f"S: logcat lines={len(seqs)} median_latency={ml:.1f}ms")
            R["P.logcat_latency"] = clamp((400.0 - ml) / (400.0 - 45.0))

        p = w.adb.popen("-s", serial, "exec-out", "screenrecord", "--output-format=h264", "-")
        try:
            out, _ = p.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            p.kill()
            out = b""
        frames = out.count(b"H264FRAME")
        R["S.screenrecord_stream"] = clamp(frames / 80.0)
        note(f"S: screenrecord frames={frames} bytes={len(out)}")

        rtts = jdwp_rtts(w, serial, 20)
        R["S.jdwp_debugger"] = 1.0 if rtts else 0.0

        # confidentiality checks on everything captured so far
        cap = w.captured()
        leaks = []
        if w.canary.encode() in cap:
            leaks.append("canary")
        if data[4096:4096 + 64] in cap:
            leaks.append("pushed-file")
        if b"hello-genadb" in cap:
            leaks.append("shell-output")
        R["S.no_plaintext_on_wire"] = 1.0 if not leaks else 0.0
        if leaks:
            note(f"S: plaintext on wire: {leaks}")
        code_forms = {code.encode(), code.replace("-", "").encode(), code.upper().encode(),
                      code.lower().encode(), hashlib.sha256(code.encode()).hexdigest().encode(),
                      hashlib.sha256(code.encode()).digest()}
        R["S.pairing_code_not_on_wire"] = 0.0 if any(f and f in cap for f in code_forms) else 1.0

        # incompressibility of the tunnel while pushing zeros
        mark_d, mark_p = len(w.dev_leg.captured("up")), len(w.phone_leg.captured("down"))
        ok0, _, _ = push_and_time(w, serial, b"\0" * (2 * 1024 * 1024), "/sdcard/zeros.bin")
        seg = w.dev_leg.captured("up")[mark_d:] + w.phone_leg.captured("down")[mark_p:]
        if ok0 and len(seg) > 1024 * 1024:
            ratio = len(zlib.compress(seg, 6)) / len(seg)
            note(f"S: zeros-push wire compress ratio={ratio:.3f}")
            R["S.ciphertext_incompressible"] = 1.0 if ratio > 0.9 else 0.0
        elif ok0:
            # tunnel compressed the payload before sending; acceptable only if no plaintext
            R["S.ciphertext_incompressible"] = R["S.no_plaintext_on_wire"]

        # reconnect later without the code (persistent pairing)
        con.kill()
        w.adb.run("disconnect", addr, timeout=5)
        dev_id = code_ev.get("device_id") or (dev.wait_event("online", 1) or {}).get("device_id")
        con2 = w.connect(extra=["--device", str(dev_id)])
        addr2 = wait_listening(con2, 20)
        if addr2 and w.adb.connect(addr2, timeout=15) is not None and w.adb.shell_ok(addr2):
            R["S.reconnect_without_code"] = 1.0
    finally:
        w.close()


def scenario_W(binary, R):
    w = World(binary, "W", leg_delay_ms=5.0)
    try:
        dev = w.device()
        ev = dev.wait_event("pairing_code", 15)
        if not ev:
            return
        code = str(ev["code"])
        n_before = dev.count()

        def mutate(c):
            chars = list(c)
            for i in range(len(chars) - 1, -1, -1):
                ch = chars[i]
                if ch.isdigit():
                    chars[i] = str((int(ch) + 1) % 10)
                    return "".join(chars)
                if ch.isalpha():
                    chars[i] = "B" if ch.upper() == "A" else "A"
                    if ch.islower():
                        chars[i] = chars[i].lower()
                    return "".join(chars)
            return c + "0"

        rejected = 0
        for i in range(3):
            bad = mutate(code) if i == 0 else mutate(mutate(code)) if i == 1 else mutate(mutate(mutate(code)))
            if bad == code:
                bad = code + "9"
            con = w.connect(f"bad{i}", extra=["--code", bad])
            if denied(w, con, w.phone, timeout=8):
                rejected += 1
        R["W.wrong_code_rejected"] = rejected / 3.0
        # correct (original) code after 3 failures must no longer work
        con = w.connect("late", extra=["--code", code])
        burned = denied(w, con, w.phone, timeout=8)
        R["W.burn_after_3_failures"] = 1.0 if (burned and rejected == 3) else 0.0
        # a fresh code should be offered and work
        ev2 = dev.wait_event("pairing_code", 10, after=n_before)
        if ev2 and str(ev2["code"]) != code:
            con = w.connect("fresh", extra=["--code", str(ev2["code"])])
            addr = wait_listening(con, 15)
            if addr and w.adb.connect(addr, 10) is not None and w.adb.shell_ok(addr):
                R["W.fresh_code_works"] = 1.0
    finally:
        w.close()


def scenario_T(binary, R):
    w = World(binary, "T", leg_delay_ms=10.0, rate_mbit=200.0)
    try:
        dev = w.device()
        ev = dev.wait_event("pairing_code", 15)
        if not ev:
            return
        con = w.connect(extra=["--code", str(ev["code"])])
        addr = wait_listening(con, 20)
        if not addr or w.adb.connect(addr, 15) is None:
            note("T: could not establish baseline session")
            return
        serial = addr

        # --- tamper: flip a bit in phone->relay direction during a pull
        data = os.urandom(6 * 1024 * 1024)
        ok, _, _ = push_and_time(w, serial, data, "/sdcard/t.bin")
        if ok:
            w.phone_leg.flip_bit_after("up", 2 * 1024 * 1024)
            out_path = os.path.join(w.root, "t-pulled.bin")
            rc, _, _ = adb_bytes(w, serial, "pull", "/sdcard/t.bin", out_path, timeout=40)
            got = open(out_path, "rb").read() if os.path.exists(out_path) else b""
            silent = (rc == 0 and got != data)
            flipped = w.phone_leg.tampered > 0
            note(f"T: tamper flipped={flipped} rc={rc} intact={got == data}")
            R["T.tamper_never_silent"] = 0.0 if (silent or not flipped) else 1.0
        # make sure session is usable again before next test
        t_end = time.time() + 15
        while time.time() < t_end and not w.adb.shell_ok(serial, 3):
            w.adb.run("connect", serial, timeout=3)
            time.sleep(0.3)

        # --- drop: kill phone-leg connections mid push
        big = os.urandom(12 * 1024 * 1024)
        result = {}

        def do_push():
            result["r"] = push_and_time(w, serial, big, "/sdcard/drop.bin", timeout=60)
        th = threading.Thread(target=do_push)
        th.start()
        t_kill = time.time() + 20
        base = w.phone_leg.bytes_dir["down"]
        while time.time() < t_kill and w.phone_leg.bytes_dir["down"] - base < 4 * 1024 * 1024 and th.is_alive():
            time.sleep(0.01)
        w.phone_leg.kill_all()
        th.join(70)
        ok = result.get("r", (False,))[0]
        if ok:
            R["T.push_survives_drop"] = 1.0
        else:
            t_end = time.time() + 15
            recovered = False
            while time.time() < t_end:
                w.adb.run("connect", serial, timeout=3)
                if w.adb.shell_ok(serial, 3):
                    recovered = True
                    break
                time.sleep(0.3)
            if recovered and push_and_time(w, serial, big[:1024 * 1024], "/sdcard/drop2.bin")[0]:
                R["T.push_survives_drop"] = 0.4
        note(f"T: push_survives_drop={R.get('T.push_survives_drop', 0)}")

        # --- outage: 4s blackout on phone leg, measure time to usable again
        w.phone_leg.outage(4.0)
        t0 = time.time()
        rec = None
        while time.time() - t0 < 25:
            if w.adb.shell_ok(serial, 3):
                rec = time.time() - t0
                break
            w.adb.run("connect", serial, timeout=3)
            time.sleep(0.25)
        if rec is not None:
            R["T.outage_recovery"] = clamp((20.0 - rec) / (20.0 - 5.0))
        note(f"T: outage recovery={rec}")
    finally:
        w.close()


def scenario_C(binary, R):
    idp = IdP()
    relay_id = "relay-" + os.urandom(4).hex()
    policy = {"relay_id": relay_id, "issuer": idp.issuer,
              "idp_ed25519_public_key": b64u(idp.pub),
              "grants": [{"user": "alice", "devices": ["dev-A", "dev-B"]},
                         {"user": "bob", "devices": []}],
              "max_session_seconds": 900}
    w = World(binary, "C", mode="corporate", adbd_mode="tls", leg_delay_ms=10.0,
              policy=policy, audit=True, admin=True)
    tokens = []
    try:
        k_dev = w.keygen("phone")
        k_devB = w.keygen("phoneB")
        k_alice = w.keygen("alice")
        k_bob = w.keygen("bob")
        k_mal = w.keygen("mallory")

        def tok(*a, **kw):
            t = idp.issue(*a, **kw)
            tokens.append(t)
            return t
        dev_tok = tok("dev-A", "device", relay_id, key=k_dev, ttl=900)
        dev = w.device(extra=["--enroll", dev_tok, "--policy", w.policy_path])
        if not dev.wait_event("online", 15):
            note("C: device never online")
            return
        # device B: MDM disallows debugging
        phoneB = FakeDevice(mode="tls", authorized_keys=[w.adb.pubkey])
        devB_tok = tok("dev-B", "device", relay_id, key=k_devB, ttl=900)
        devB = w.device("phoneB", phone=phoneB, extra=["--enroll", devB_tok, "--policy", w.policy_path,
                                                       "--debug-policy", "disallowed"])
        blocked = devB.wait_event("blocked", 10)

        lazy_ok = w.phone.connections == 0  # nobody connected yet -> adbd untouched

        alice_tok = tok("alice", "user", relay_id, key=k_alice)
        con = w.connect("alice", extra=["--device", "dev-A", "--identity", alice_tok, "--policy", w.policy_path])
        addr = wait_listening(con, 20)
        authorized = 0.0
        serial = None
        if addr and w.adb.connect(addr, 15) is not None:
            serial = addr
            rc2, out2, _ = adb_bytes(w, serial, "shell", "cat-canary")
            sh = out2.strip() == w.canary.encode()
            data = os.urandom(2 * 1024 * 1024)
            pok = push_and_time(w, serial, data, "/sdcard/corp.bin")[0]
            seqs, _ = logcat_sample(w, serial, 1.5)
            authorized = (sh + pok + (len(seqs) > 20)) / 3.0
        R["C.authorized_session"] = authorized
        note(f"C: authorized={authorized:.2f} addr={addr}")
        gate = 1.0 if authorized == 1.0 else 0.0

        if addr:
            loop_only = addr.startswith("127.0.0.1:")
            for p in w.procs[1:]:
                if p.alive():
                    for ip, port in listening_sockets(p.p.pid):
                        if ip not in ("127.0.0.1", "::1"):
                            loop_only = False
                            note(f"C: {p.name} listens on {ip}:{port}")
            R["C.loopback_and_lazy_adbd"] = (0.5 if loop_only else 0) + (0.5 if lazy_ok else 0)

        # B: debugging disallowed
        alice_tok2 = tok("alice", "user", relay_id, key=k_alice)
        conB = w.connect("alice", extra=["--device", "dev-B", "--identity", alice_tok2, "--policy", w.policy_path])
        dB = denied(w, conB, phoneB)
        R["C.debugging_disallowed"] = gate * ((1.0 if blocked else 0) * 0.3 + (0.7 if dB and phoneB.connections == 0 else 0))
        phoneB.close()

        checks = {
            "C.deny_unauthorized_user": ("bob", tok("bob", "user", relay_id, key=k_bob)),
            "C.deny_expired": ("alice", tok("alice", "user", relay_id, key=k_alice, ttl=-60, iat=int(time.time()) - 700)),
            "C.deny_forged": ("alice", tok("alice", "user", relay_id, key=k_alice,
                                           signer=Ed25519PrivateKey.generate())),
            "C.deny_wrong_audience": ("alice", tok("alice", "user", "some-other-relay", key=k_alice)),
            "C.deny_stolen_token": ("mallory", tok("alice", "user", relay_id, key=k_alice)),
            "C.deny_no_identity": ("mallory", None),
        }
        for name, (who, t) in checks.items():
            extra = ["--device", "dev-A", "--policy", w.policy_path]
            if t:
                extra += ["--identity", t]
            c = w.connect(who, extra=extra)
            R[name] = gate * (1.0 if denied(w, c, w.phone) else 0.0)
            if not R[name] and gate:
                note(f"C: {name} NOT denied")
        # authorized session must still work after the attacks
        if serial and not w.adb.shell_ok(serial, 5):
            note("C: authorized session broken by negative tests")
            for k in checks:
                R[k] = R.get(k, 0) * 0.5

        # revoke alice
        if serial and w.admin_addr:
            req = urllib.request.Request(f"http://{w.admin_addr}/v1/revoke", method="POST",
                                         data=json.dumps({"user": "alice"}).encode(),
                                         headers={"Authorization": f"Bearer {w.admin_token}",
                                                  "Content-Type": "application/json"})
            t0 = time.time()
            try:
                urllib.request.urlopen(req, timeout=5).read()
                killed_at = None
                while time.time() - t0 < 8:
                    if not w.adb.shell_ok(serial, 2):
                        killed_at = time.time() - t0
                        break
                    time.sleep(0.2)
                if killed_at is not None:
                    R["C.revoke_kills_session"] = gate * clamp((6.0 - killed_at) / 5.0)
                note(f"C: revoke kill time={killed_at}")
                c = w.spawn([binary, "connect", "--relay", w.dev_leg.addr, "--state", w.state("alice"),
                             "--listen", "127.0.0.1:0", "--mode", "corporate", "--device", "dev-A",
                             "--policy", w.policy_path, "--identity", tok("alice", "user", relay_id, key=k_alice)],
                            "connect-alice-revoked")
                R["C.revoke_blocks_new"] = gate * (1.0 if denied(w, c, w.phone) else 0.0)
            except Exception as e:
                note(f"C: admin revoke failed: {e}")

        # audit
        time.sleep(0.5)
        if w.audit_path and os.path.exists(w.audit_path):
            raw = open(w.audit_path).read()
            lines = []
            for ln in raw.splitlines():
                try:
                    lines.append(json.loads(ln))
                except ValueError:
                    pass
            txt = json.dumps(lines)
            has_start = any("start" in str(e.get("event", "")) and e.get("user") == "alice"
                            and e.get("device") == "dev-A" for e in lines)
            has_deny = any("den" in str(e.get("event", "")) and e.get("user") == "bob" for e in lines)
            has_end = any(any(k in str(e.get("event", "")) for k in ("end", "revok")) for e in lines)
            secrets = any(t.split(".")[2] in raw for t in tokens) or w.canary in raw or w.admin_token in raw
            R["C.audit_log"] = gate * (0.0 if secrets else (has_start + has_deny + has_end) / 3.0)
            note(f"C: audit start={has_start} deny={has_deny} end={has_end} secrets={secrets}")
    finally:
        w.close()


def scenario_L(binary, R):
    w = World(binary, "L", leg_delay_ms=60.0)
    lan_proxy = None
    try:
        lan_port = free_port()
        lan_proxy = Proxy(("127.0.0.1", lan_port), 1.0, 0, "L-lan")
        dev = w.device(extra=["--lan-listen", f"127.0.0.1:{lan_port}", "--lan-advertise", lan_proxy.addr])
        ev = dev.wait_event("pairing_code", 15)
        if not ev:
            return
        con = w.connect(extra=["--code", str(ev["code"])])
        addr = wait_listening(con, 25)
        if not addr or w.adb.connect(addr, 20) is None:
            return
        time.sleep(1.0)
        rtts = jdwp_rtts(w, addr, 20)
        if rtts:
            m = median(rtts)
            note(f"L: jdwp median rtt={m:.1f}ms (relay path ~250ms, LAN ~5ms)")
            R["L.lan_direct_latency"] = clamp((250.0 - m) / (250.0 - 20.0))
    finally:
        if lan_proxy:
            lan_proxy.close()
        w.close()


SCENARIOS = [scenario_S, scenario_W, scenario_T, scenario_C, scenario_L]


def run_all(binary):
    R = {}
    errors = []

    def wrap(fn):
        try:
            fn(binary, R)
        except Exception as e:
            errors.append(f"{fn.__name__}: {e!r}")
            note(traceback.format_exc()[-800:])
    threads = [threading.Thread(target=wrap, args=(fn,), daemon=True) for fn in SCENARIOS]
    for t in threads:
        t.start()
    deadline = time.time() + 165
    for t in threads:
        t.join(max(0, deadline - time.time()))
    return R, errors


def evaluate():
    start_time = time.time()
    try:
        from solution import run_solution
        built = run_solution()
        binary = built["binary"]
        R, errors = run_all(binary)
        elapsed = time.time() - start_time
        for line in LOG:
            print("NOTE", line)
        for e in errors:
            print("ERROR", e)
        score = 0.0
        for k, wgt in WEIGHTS.items():
            v = clamp(float(R.get(k, 0.0)))
            score += wgt * v
            print(f"CHECK {k:34s} {v:5.2f} x {wgt:>2} = {wgt * v:6.2f}")
        if elapsed > TIME_LIMIT_SECONDS:
            print(f"STATUS: TIMEOUT ({elapsed:.2f}s > {TIME_LIMIT_SECONDS}s)")
            print("SCORE: -999999.0")
            return
        print(f"STATUS: SUCCESS ({elapsed:.2f}s)")
        print(f"SCORE: {score:.6f}")
    except Exception as e:
        print(f"STATUS: CRASH ({e})")
        traceback.print_exc()
        print("SCORE: -999999.0")


if __name__ == "__main__":
    evaluate()
    sys.stdout.flush()
    os._exit(0)

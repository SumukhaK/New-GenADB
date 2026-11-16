"""
User-space network impairment proxy for the New-GenADB harness.

Every byte that travels between an agent (desktop or device) and the relay, or
over the simulated LAN path, passes through one of these proxies.  A proxy can:
  * add one-way latency per direction and cap bandwidth (token bucket)
  * record all bytes in both directions (used for confidentiality checks)
  * kill all live connections (simulates a network switch / NAT rebinding)
  * refuse new connections for a while (simulates an outage)
  * flip one bit at a chosen offset in one direction (active tampering)

Agents can only make *outbound* connections to the addresses they are given;
the harness never hands the desktop an address of the device or vice versa
except through the explicit LAN scenario.  This models carrier NAT.

This file is part of the immutable harness. Do not modify during Phase 2.
"""
import socket
import threading
import time
import collections
import heapq


class Pipe:
    def __init__(self, proxy, src, dst, direction):
        self.proxy, self.src, self.dst, self.direction = proxy, src, dst, direction
        self.q = []
        self.cv = threading.Condition()
        self.closed = False
        self.seq = 0
        self.bytes = 0

    def reader(self):
        p = self.proxy
        try:
            while True:
                data = self.src.recv(65536)
                if not data:
                    break
                now = time.time()
                with p.lock:
                    if p.capture_enabled:
                        p.capture[self.direction].append(data)
                    off = p.tamper.get(self.direction)
                    if off is not None and p.bytes_dir[self.direction] <= off < p.bytes_dir[self.direction] + len(data):
                        i = off - p.bytes_dir[self.direction]
                        data = data[:i] + bytes([data[i] ^ 0x10]) + data[i + 1:]
                        p.tamper.pop(self.direction)
                        p.tampered += 1
                    p.bytes_dir[self.direction] += len(data)
                with self.cv:
                    self.seq += 1
                    heapq.heappush(self.q, (now + p.delay, self.seq, data))
                    self.cv.notify()
        except OSError:
            pass
        finally:
            with self.cv:
                self.seq += 1
                heapq.heappush(self.q, (time.time() + p.delay, self.seq, None))
                self.cv.notify()

    def writer(self):
        p = self.proxy
        try:
            while True:
                with self.cv:
                    while not self.q:
                        self.cv.wait()
                    due, _, data = self.q[0]
                    now = time.time()
                    if due > now:
                        self.cv.wait(due - now)
                        continue
                    heapq.heappop(self.q)
                if data is None:
                    try:
                        self.dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    return
                if p.rate:
                    # simple pacing: sleep the serialisation time of this chunk
                    time.sleep(len(data) / p.rate)
                self.dst.sendall(data)
        except OSError:
            pass
        finally:
            for s in (self.src, self.dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass


class Proxy:
    def __init__(self, target, delay_ms=0.0, rate_mbit=0.0, name="proxy", capture=True):
        self.target = target
        self.delay = delay_ms / 1000.0
        self.rate = rate_mbit * 1e6 / 8 if rate_mbit else 0
        self.name = name
        self.lock = threading.Lock()
        self.capture_enabled = capture
        self.capture = {"up": [], "down": []}
        self.bytes_dir = collections.Counter()
        self.tamper = {}
        self.tampered = 0
        self.blocked_until = 0.0
        self.conns = set()
        self.total_conns = 0
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.addr = f"127.0.0.1:{self.port}"
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop:
            try:
                c, _ = self.srv.accept()
            except OSError:
                return
            if time.time() < self.blocked_until:
                c.close()
                continue
            try:
                s = socket.create_connection(self.target, timeout=5)
                s.settimeout(None)
            except OSError:
                c.close()
                continue
            for x in (c, s):
                x.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            with self.lock:
                self.conns.add((c, s))
                self.total_conns += 1
            up = Pipe(self, c, s, "up")      # agent -> target
            down = Pipe(self, s, c, "down")  # target -> agent
            for pipe in (up, down):
                threading.Thread(target=pipe.reader, daemon=True).start()
                threading.Thread(target=pipe.writer, daemon=True).start()

    def captured(self, direction=None):
        with self.lock:
            if direction:
                return b"".join(self.capture[direction])
            return b"".join(self.capture["up"]) + b"".join(self.capture["down"])

    def kill_all(self):
        with self.lock:
            conns = list(self.conns)
            self.conns.clear()
        for c, s in conns:
            for x in (c, s):
                try:
                    x.shutdown(socket.SHUT_RDWR)
                    x.close()
                except OSError:
                    pass

    def outage(self, seconds):
        self.blocked_until = time.time() + seconds
        self.kill_all()

    def flip_bit_after(self, direction, extra_bytes):
        with self.lock:
            self.tamper[direction] = self.bytes_dir[direction] + extra_bytes

    def close(self):
        self._stop = True
        try:
            self.srv.close()
        except OSError:
            pass
        self.kill_all()

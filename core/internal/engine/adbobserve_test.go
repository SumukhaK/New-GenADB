package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func amsg(cmd, a0, a1 uint32, payload []byte) []byte {
	b := make([]byte, 24+len(payload))
	binary.LittleEndian.PutUint32(b[0:], cmd)
	binary.LittleEndian.PutUint32(b[4:], a0)
	binary.LittleEndian.PutUint32(b[8:], a1)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(payload)))
	binary.LittleEndian.PutUint32(b[20:], cmd^0xFFFFFFFF)
	copy(b[24:], payload)
	return b
}

func syncReq(id string, body []byte) []byte {
	b := make([]byte, 8+len(body))
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], uint32(len(body)))
	copy(b[8:], body)
	return b
}

func syncHdr(id string, n uint32) []byte {
	b := make([]byte, 8)
	copy(b, id)
	binary.LittleEndian.PutUint32(b[4:], n)
	return b
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type opLog struct{ ops []adbOp }

func newObs() (*adbObserver, *opLog) {
	l := &opLog{}
	return newADBObserver(nil, func(op adbOp) { l.ops = append(l.ops, op) }, "s1"), l
}

// feedSplit delivers b in small, uneven chunks to exercise reassembly.
func feedSplit(o *adbObserver, b []byte, up bool) {
	for i := 0; len(b) > 0; i++ {
		n := 1 + (i*7)%13
		if n > len(b) {
			n = len(b)
		}
		o.feed(b[:n], up)
		b = b[n:]
	}
}

func TestObserverPushAndPull(t *testing.T) {
	o, l := newObs()
	content := []byte(strings.Repeat("genadb-", 5000))
	pulled := []byte("hello from the device")
	// host: OPEN sync, SEND path,mode + DATA chunks + DONE, then RECV
	feedSplit(o, amsg(aCNXN, 0x01000001, 256*1024, []byte("host::\x00")), true)
	feedSplit(o, amsg(aOPEN, 7, 0, []byte("sync:\x00")), true)
	feedSplit(o, amsg(aOKAY, 99, 7, nil), false)
	half := len(content) / 2
	feedSplit(o, amsg(aWRTE, 7, 99, cat(syncReq("SEND", []byte("/sdcard/a.bin,33206")), syncReq("DATA", content[:half]))), true)
	feedSplit(o, amsg(aWRTE, 7, 99, cat(syncReq("DATA", content[half:]), syncHdr("DONE", 1700000000))), true)
	feedSplit(o, amsg(aWRTE, 99, 7, syncHdr("OKAY", 0)), false)
	// pull: STAT v1 then RECV
	feedSplit(o, amsg(aWRTE, 7, 99, cat(syncReq("STAT", []byte("/sdcard/b.txt")), syncReq("RECV", []byte("/sdcard/b.txt")))), true)
	stat := make([]byte, 16)
	copy(stat, "STAT")
	feedSplit(o, amsg(aWRTE, 99, 7, cat(stat, syncReq("DATA", pulled[:5]))), false)
	feedSplit(o, amsg(aWRTE, 99, 7, cat(syncReq("DATA", pulled[5:]), syncHdr("DONE", 0))), false)
	feedSplit(o, amsg(aWRTE, 7, 99, syncHdr("QUIT", 0)), true)
	feedSplit(o, amsg(aCLSE, 7, 99, nil), true)

	if len(l.ops) != 2 {
		t.Fatalf("ops = %+v", l.ops)
	}
	push, pull := l.ops[0], l.ops[1]
	if push.kind != "push" || push.path != "/sdcard/a.bin" || push.up != int64(len(content)) || push.sha256 != sum(content) || push.failed {
		t.Errorf("push = %+v", push)
	}
	if pull.kind != "pull" || pull.path != "/sdcard/b.txt" || pull.down != int64(len(pulled)) || pull.sha256 != sum(pulled) || pull.failed {
		t.Errorf("pull = %+v", pull)
	}
	if push.session != "s1" {
		t.Errorf("session = %q", push.session)
	}
}

func TestObserverPushRejected(t *testing.T) {
	o, l := newObs()
	o.feed(amsg(aOPEN, 3, 0, []byte("sync:\x00")), true)
	o.feed(amsg(aWRTE, 3, 9, cat(syncReq("SEND", []byte("/system/x,420")), syncReq("DATA", []byte("abc")), syncHdr("DONE", 1))), true)
	o.feed(amsg(aWRTE, 9, 3, syncReq("FAIL", []byte("Read-only file system"))), false)
	o.feed(amsg(aCLSE, 3, 9, nil), true)
	if len(l.ops) != 1 || !l.ops[0].failed || l.ops[0].sha256 != "" {
		t.Fatalf("ops = %+v", l.ops)
	}
}

func TestObserverV2Compressed(t *testing.T) {
	o, l := newObs()
	o.feed(amsg(aOPEN, 3, 0, []byte("sync:\x00")), true)
	setup := make([]byte, 12)
	copy(setup, "SND2")
	binary.LittleEndian.PutUint32(setup[8:], 1) // brotli
	o.feed(amsg(aWRTE, 3, 9, cat(syncReq("SND2", []byte("/sdcard/c")), setup, syncReq("DATA", []byte("zz")), syncHdr("DONE", 1))), true)
	o.feed(amsg(aWRTE, 9, 3, syncHdr("OKAY", 0)), false)
	rsetup := make([]byte, 8)
	copy(rsetup, "RCV2")
	o.feed(amsg(aWRTE, 3, 9, cat(syncReq("RCV2", []byte("/sdcard/d")), rsetup)), true)
	o.feed(amsg(aWRTE, 9, 3, cat(syncReq("DATA", []byte("plain")), syncHdr("DONE", 0))), false)
	o.feed(amsg(aCLSE, 3, 9, nil), true)
	if len(l.ops) != 2 {
		t.Fatalf("ops = %+v", l.ops)
	}
	if l.ops[0].sha256 != "" || l.ops[0].up != 2 {
		t.Errorf("compressed push should carry no content hash: %+v", l.ops[0])
	}
	if l.ops[1].kind != "pull" || l.ops[1].path != "/sdcard/d" || l.ops[1].sha256 != sum([]byte("plain")) {
		t.Errorf("uncompressed v2 pull: %+v", l.ops[1])
	}
}

func TestObserverShellInstallForward(t *testing.T) {
	o, l := newObs()
	apk := []byte("PK\x03\x04 fake apk bytes")
	o.feed(amsg(aOPEN, 1, 0, []byte("shell,v2,TERM=xterm,raw:API_KEY=hunter2 getprop ro.serialno\x00")), true)
	o.feed(amsg(aWRTE, 50, 1, []byte("XYZ\n")), false)
	o.feed(amsg(aCLSE, 50, 1, nil), false)
	o.feed(amsg(aOPEN, 2, 0, []byte("exec:cmd package install -S 21\x00")), true)
	o.feed(amsg(aWRTE, 2, 51, apk), true)
	o.feed(amsg(aCLSE, 2, 51, nil), true)
	o.feed(amsg(aOPEN, 4, 0, []byte("tcp:8080\x00")), true)
	o.feed(amsg(aCLSE, 0, 4, nil), false) // refused
	o.feed(amsg(aOPEN, 5, 0, []byte("shell:\x00")), true)
	o.finish() // session ends with the interactive shell still open

	want := []struct{ kind, path, cmd string }{
		{"shell", "", "getprop"}, {"install", "", "cmd"}, {"forward", "tcp:8080", ""}, {"shell", "", "(interactive)"},
	}
	if len(l.ops) != len(want) {
		t.Fatalf("ops = %+v", l.ops)
	}
	for i, w := range want {
		g := l.ops[i]
		if g.kind != w.kind || g.path != w.path || g.command != w.cmd {
			t.Errorf("op %d = %+v, want %+v", i, g, w)
		}
	}
	for _, op := range l.ops {
		for _, f := range []string{op.command, op.path} {
			if strings.Contains(f, "hunter2") || strings.Contains(f, "API_KEY") || strings.Contains(f, "ro.serialno") {
				t.Fatalf("argument leaked into audit: %+v", op)
			}
		}
	}
	if l.ops[1].sha256 != sum(apk) || l.ops[1].up != int64(len(apk)) {
		t.Errorf("install = %+v", l.ops[1])
	}
	if !l.ops[2].failed || !l.ops[3].failed {
		t.Errorf("refused forward / interrupted shell should be failed: %+v", l.ops)
	}
}

func TestObserverStopsOnTLS(t *testing.T) {
	o, l := newObs()
	o.feed(amsg(aSTLS, 0x01000000, 0, nil), false)
	o.feed(amsg(aOPEN, 1, 0, []byte("shell:id\x00")), true)
	o.feed([]byte("\x16\x03\x01 random tls bytes ............................"), true)
	o.feed(amsg(aCLSE, 1, 2, nil), true)
	o.finish()
	if len(l.ops) != 0 {
		t.Fatalf("observer must go quiet after STLS: %+v", l.ops)
	}
	up, down := o.totals()
	if up == 0 || down == 0 {
		t.Fatalf("byte totals must still count: %d %d", up, down)
	}
}

func TestObserverGarbageIsHarmless(t *testing.T) {
	o, l := newObs()
	o.feed([]byte("this is not adb at all, just some bytes that are long enough"), true)
	o.feed(amsg(aOPEN, 1, 0, []byte("shell:id\x00")), true)
	o.feed(amsg(aCLSE, 1, 2, nil), true)
	if len(l.ops) != 0 {
		t.Fatalf("ops = %+v", l.ops)
	}
}

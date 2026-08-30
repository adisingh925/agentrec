package record

import (
	"encoding/binary"
	"testing"
)

/* TestDecode* validate Decode's hand-written offset parsing against known raw records. */
func TestDecodeOpen(t *testing.T) {
	le := binary.LittleEndian
	rec := make([]byte, RawEventSize)
	le.PutUint64(rec[0:], 111)
	le.PutUint64(rec[8:], 222)
	le.PutUint64(rec[16:], 333)
	le.PutUint32(rec[24:], 44)
	le.PutUint32(rec[28:], 55)
	le.PutUint32(rec[32:], 66)
	le.PutUint32(rec[36:], EvtOpen)
	le.PutUint32(rec[44:], 0o100) /* O_CREAT -> write */
	copy(rec[80:96], "bash\x00")
	path := "/etc/passwd"
	copy(rec[96:], append([]byte(path), 0))
	le.PutUint32(rec[40:], uint32(len(path)+1))

	e, err := Decode(rec)
	if err != nil {
		t.Fatal(err)
	}
	if e.Ts != 111 || e.Session != 222 || e.Call != 333 || e.Pid != 44 || e.Tid != 55 || e.Ppid != 66 {
		t.Fatalf("scalars: %+v", e)
	}
	if e.Type != "open" || e.Comm != "bash" || e.Path != "/etc/passwd" || !e.Write {
		t.Fatalf("open: %+v", e)
	}
}

func TestDecodeConnectV4(t *testing.T) {
	le := binary.LittleEndian
	rec := make([]byte, RawEventSize)
	le.PutUint32(rec[36:], EvtConnect)
	le.PutUint32(rec[56:], 443)
	le.PutUint32(rec[60:], 2)
	copy(rec[64:68], []byte{1, 2, 3, 4})
	e, err := Decode(rec)
	if err != nil {
		t.Fatal(err)
	}
	if e.Family != "ipv4" || e.Dest != "1.2.3.4:443" {
		t.Fatalf("connect v4: %+v", e)
	}
}

func TestDecodeExecArgv(t *testing.T) {
	le := binary.LittleEndian
	rec := make([]byte, RawEventSize)
	le.PutUint32(rec[36:], EvtExec)
	payload := "/bin/sh\x00-c\x00echo hi\x00"
	copy(rec[96:], payload)
	le.PutUint32(rec[40:], uint32(len(payload)))
	e, err := Decode(rec)
	if err != nil {
		t.Fatal(err)
	}
	if e.Type != "exec" || e.Path != "/bin/sh" {
		t.Fatalf("exec path: %+v", e)
	}
	if len(e.Argv) != 2 || e.Argv[0] != "-c" || e.Argv[1] != "echo hi" {
		t.Fatalf("exec argv: %+v", e.Argv)
	}
}

func TestDecodeShort(t *testing.T) {
	if _, err := Decode(make([]byte, 10)); err == nil {
		t.Fatal("expected error on short record")
	}
}

/* TestDecodeHeaderOnly checks Decode accepts 96-byte header-only records (fork/exit/inet connect). */
func TestDecodeHeaderOnly(t *testing.T) {
	le := binary.LittleEndian

	fork := make([]byte, rawHeaderSize)
	le.PutUint32(fork[36:], EvtFork)
	le.PutUint32(fork[24:], 1234)
	copy(fork[80:96], "node\x00")
	e, err := Decode(fork)
	if err != nil {
		t.Fatalf("96-byte fork: %v", err)
	}
	if e.Type != "fork" || e.Pid != 1234 || e.Comm != "node" {
		t.Fatalf("fork: %+v", e)
	}

	conn := make([]byte, rawHeaderSize)
	le.PutUint32(conn[36:], EvtConnect)
	le.PutUint32(conn[56:], 8443)
	le.PutUint32(conn[60:], 2)
	copy(conn[64:68], []byte{10, 0, 0, 9})
	e, err = Decode(conn)
	if err != nil {
		t.Fatalf("96-byte connect: %v", err)
	}
	if e.Family != "ipv4" || e.Dest != "10.0.0.9:8443" {
		t.Fatalf("connect: %+v", e)
	}

	/* One byte short of the header is rejected. */
	if _, err := Decode(make([]byte, rawHeaderSize-1)); err == nil {
		t.Fatal("expected error just under header size")
	}
}

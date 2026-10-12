package protocol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func mustKey(t *testing.T) Key {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func handshake(t *testing.T) (client, server *Session) {
	t.Helper()
	clientKey, serverKey := mustKey(t), mustKey(t)
	hs, initMsg, err := CreateInitiation(clientKey, serverKey.Public(), 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	init, err := ConsumeInitiation(serverKey, initMsg)
	if err != nil {
		t.Fatal(err)
	}
	if init.PeerStatic != clientKey.Public() {
		t.Fatal("server learned the wrong client identity")
	}
	server, resp, err := init.CreateResponse(9)
	if err != nil {
		t.Fatal(err)
	}
	client, err = hs.ConsumeResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if client.RemoteIndex != 9 || server.RemoteIndex != 7 {
		t.Fatalf("indices: client remote %d, server remote %d", client.RemoteIndex, server.RemoteIndex)
	}
	return client, server
}

func TestKeyRoundTrip(t *testing.T) {
	k := mustKey(t)
	got, err := ParseKey(k.String())
	if err != nil || got != k {
		t.Fatalf("ParseKey(String()) = %v, %v", got, err)
	}
	if _, err := ParseKey("dG9vIHNob3J0"); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestDataBothDirections(t *testing.T) {
	client, server := handshake(t)
	for _, tc := range []struct {
		name     string
		from, to *Session
	}{{"client to server", client, server}, {"server to client", server, client}} {
		for _, payload := range [][]byte{[]byte("hello through the tunnel"), nil} {
			msg, err := tc.from.Seal(payload)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(msg, []byte("hello")) {
				t.Fatalf("%s: plaintext visible on the wire", tc.name)
			}
			got, err := tc.to.Open(msg)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("%s: got %q, want %q", tc.name, got, payload)
			}
		}
	}
}

func TestReplayRejected(t *testing.T) {
	client, server := handshake(t)
	msg, _ := client.Seal([]byte("once"))
	if _, err := server.Open(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Open(msg); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: got %v, want ErrReplay", err)
	}
}

func TestReorderingAccepted(t *testing.T) {
	client, server := handshake(t)
	var msgs [][]byte
	for range 100 {
		m, _ := client.Seal([]byte("x"))
		msgs = append(msgs, m)
	}
	// Deliver in reverse order: every packet is within the window.
	for i := len(msgs) - 1; i >= 0; i-- {
		if _, err := server.Open(msgs[i]); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
}

func TestTooOldRejected(t *testing.T) {
	client, server := handshake(t)
	old, _ := client.Seal([]byte("old"))
	for range windowSize + 1 {
		m, _ := client.Seal(nil)
		if _, err := server.Open(m); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server.Open(old); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v, want ErrReplay", err)
	}
}

func TestTamperingDetected(t *testing.T) {
	client, server := handshake(t)
	msg, _ := client.Seal([]byte("pay alice $10"))
	msg[len(msg)-20] ^= 1
	if _, err := server.Open(msg); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("got %v, want ErrDecrypt", err)
	}
	// A forged packet must not burn its counter: the genuine one still works.
	msg[len(msg)-20] ^= 1
	if _, err := server.Open(msg); err != nil {
		t.Fatalf("genuine packet after forgery: %v", err)
	}
}

func TestWrongServerKey(t *testing.T) {
	clientKey, serverKey, otherKey := mustKey(t), mustKey(t), mustKey(t)
	_, initMsg, _ := CreateInitiation(clientKey, otherKey.Public(), 1, time.Now())
	if _, err := ConsumeInitiation(serverKey, initMsg); err == nil {
		t.Fatal("server accepted an initiation meant for another key")
	}
}

func TestImpostorServerRejected(t *testing.T) {
	clientKey, serverKey, impostorKey := mustKey(t), mustKey(t), mustKey(t)
	hs, _, _ := CreateInitiation(clientKey, serverKey.Public(), 1, time.Now())
	// The impostor can't decrypt the initiation, so it can only send a
	// response built from a handshake with itself.
	_, fakeInit, _ := CreateInitiation(clientKey, impostorKey.Public(), 1, time.Now())
	init, err := ConsumeInitiation(impostorKey, fakeInit)
	if err != nil {
		t.Fatal(err)
	}
	_, resp, _ := init.CreateResponse(2)
	if _, err := hs.ConsumeResponse(resp); err == nil {
		t.Fatal("client accepted a response from the wrong server")
	}
}

func TestTamperedInitiation(t *testing.T) {
	clientKey, serverKey := mustKey(t), mustKey(t)
	_, initMsg, _ := CreateInitiation(clientKey, serverKey.Public(), 1, time.Now())
	for _, i := range []int{10, 50, 100} {
		m := bytes.Clone(initMsg)
		m[i] ^= 1
		if _, err := ConsumeInitiation(serverKey, m); err == nil {
			t.Fatalf("flipping byte %d went unnoticed", i)
		}
	}
}

func TestTimestampOrder(t *testing.T) {
	now := time.Now()
	a, b := NewTimestamp(now), NewTimestamp(now.Add(time.Nanosecond))
	if !b.After(a) || a.After(b) || a.After(a) {
		t.Fatal("timestamp ordering is wrong")
	}
}

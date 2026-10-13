package protocol

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	k, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return NewIdentity(k)
}

func allowAll(PublicKey) bool { return true }

func handshake(t *testing.T) (client, server *Session) {
	t.Helper()
	clientID, serverID := newIdentity(t), newIdentity(t)
	hs, err := CreateInitiation(clientID, serverID.Public, 7, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	init, err := ConsumeInitiation(serverID, hs.Message, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	if init.Peer != clientID.Public {
		t.Fatal("server learned the wrong client identity")
	}
	server, resp, err := init.CreateResponse(serverID, 9)
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

func TestKeys(t *testing.T) {
	k, _ := GeneratePrivateKey()
	got, err := ParsePrivateKey(k.String())
	if err != nil || got != k {
		t.Fatalf("ParsePrivateKey(String()) = %v, %v", got, err)
	}
	pub := k.Public()
	if gotPub, err := ParsePublicKey(pub.String()); err != nil || gotPub != pub {
		t.Fatalf("ParsePublicKey(String()) = %v, %v", gotPub, err)
	}
	if k.Public() != pub {
		t.Fatal("public key derivation is not deterministic")
	}
	if _, err := ParsePublicKey(k.String()); err == nil {
		t.Fatal("a 32-byte key was accepted as a public key")
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
	clientID, serverID, otherID := newIdentity(t), newIdentity(t), newIdentity(t)
	hs, _ := CreateInitiation(clientID, otherID.Public, 1, time.Now())
	if _, err := ConsumeInitiation(serverID, hs.Message, allowAll); err == nil {
		t.Fatal("server accepted an initiation meant for another key")
	}
}

func TestUnknownPeerStopsEarly(t *testing.T) {
	clientID, serverID := newIdentity(t), newIdentity(t)
	hs, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
	var asked PublicKey
	_, err := ConsumeInitiation(serverID, hs.Message, func(p PublicKey) bool { asked = p; return false })
	if !errors.Is(err, ErrUnknownPeer) || asked != clientID.Public {
		t.Fatalf("got %v (asked about %v), want ErrUnknownPeer for the client", err, asked)
	}
}

func TestImpostorServerRejected(t *testing.T) {
	clientID, serverID, impostorID := newIdentity(t), newIdentity(t), newIdentity(t)
	hs, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
	// The impostor can't decrypt the initiation, so it can only send a
	// response built from a handshake with itself.
	fake, _ := CreateInitiation(clientID, impostorID.Public, 1, time.Now())
	init, err := ConsumeInitiation(impostorID, fake.Message, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	_, resp, _ := init.CreateResponse(impostorID, 2)
	if _, err := hs.ConsumeResponse(resp); err == nil {
		t.Fatal("client accepted a response from the wrong server")
	}
}

// A signature from the wrong ML-DSA key must be rejected even when the
// X25519 part of the identity is right. This is what stops an attacker who
// can break X25519 (for example with a quantum computer).
func TestPostQuantumAuthentication(t *testing.T) {
	clientID, serverID := newIdentity(t), newIdentity(t)
	forger := newIdentity(t)
	forger.x25519 = clientID.x25519 // the attacker has recovered the X25519 key...
	forger.Public = clientID.Public // ...and claims the client's public key

	hs, _ := CreateInitiation(forger, serverID.Public, 1, time.Now())
	_, err := ConsumeInitiation(serverID, hs.Message, func(p PublicKey) bool { return p == clientID.Public })
	if err == nil {
		t.Fatal("server accepted an initiation signed with the wrong ML-DSA key")
	}

	// Same for the server side.
	forgedServer := newIdentity(t)
	forgedServer.x25519 = serverID.x25519
	forgedServer.Public = serverID.Public
	hs, _ = CreateInitiation(clientID, serverID.Public, 1, time.Now())
	init, err := ConsumeInitiation(forgedServer, hs.Message, allowAll)
	if err != nil {
		t.Fatal(err)
	}
	_, resp, _ := init.CreateResponse(forgedServer, 2)
	if _, err := hs.ConsumeResponse(resp); !errors.Is(err, ErrSignature) {
		t.Fatalf("got %v, want ErrSignature", err)
	}
}

func TestTamperedInitiation(t *testing.T) {
	clientID, serverID := newIdentity(t), newIdentity(t)
	hs, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
	for _, i := range []int{10, initKEM + 5, initStatic + 5, initPayload + 5, initMACs - 1} {
		m := bytes.Clone(hs.Message)
		m[i] ^= 1
		if _, err := ConsumeInitiation(serverID, m, allowAll); err == nil {
			t.Fatalf("flipping byte %d went unnoticed", i)
		}
	}
}

func TestTamperedResponse(t *testing.T) {
	clientID, serverID := newIdentity(t), newIdentity(t)
	for _, i := range []int{respEph + 5, respKEM + 5, respPayload + 5, respMACs - 1} {
		hs, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
		init, err := ConsumeInitiation(serverID, hs.Message, allowAll)
		if err != nil {
			t.Fatal(err)
		}
		_, resp, _ := init.CreateResponse(serverID, 2)
		resp[i] ^= 1
		if _, err := hs.ConsumeResponse(resp); err == nil {
			t.Fatalf("flipping response byte %d went unnoticed", i)
		}
	}
}

func TestNoAmplification(t *testing.T) {
	if ResponseSize >= InitiationSize {
		t.Fatalf("response (%d) must be smaller than initiation (%d)", ResponseSize, InitiationSize)
	}
	if CookieReplySize >= FragmentPayload {
		t.Fatal("cookie reply must be smaller than one initiation fragment")
	}
}

func TestMACs(t *testing.T) {
	clientID, serverID := newIdentity(t), newIdentity(t)
	hs, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
	msg := hs.Message
	AddMACs(msg, serverID.Public, nil)
	checker := NewCookieChecker(serverID.Public)
	if !checker.CheckMAC1(msg) {
		t.Fatal("valid mac1 rejected")
	}
	if CheckMAC1(msg, clientID.Public) {
		t.Fatal("mac1 accepted for the wrong receiver")
	}
	if checker.CheckMAC2(msg, "1.2.3.4:5") {
		t.Fatal("missing mac2 accepted")
	}

	// Under load: the server replies with a cookie, the client retries with it.
	reply, err := checker.CreateReply(msg, "1.2.3.4:5")
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := ConsumeCookieReply(reply, msg, serverID.Public)
	if err != nil {
		t.Fatal(err)
	}
	AddMACs(msg, serverID.Public, cookie)
	if !checker.CheckMAC1(msg) || !checker.CheckMAC2(msg, "1.2.3.4:5") {
		t.Fatal("valid mac2 rejected")
	}
	if checker.CheckMAC2(msg, "6.7.8.9:5") {
		t.Fatal("cookie accepted from a different address")
	}
	// The handshake itself is unaffected by the MACs.
	if _, err := ConsumeInitiation(serverID, msg, allowAll); err != nil {
		t.Fatal(err)
	}
}

func TestCookieReplyForSomeoneElse(t *testing.T) {
	clientID, serverID := newIdentity(t), newIdentity(t)
	hs1, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
	hs2, _ := CreateInitiation(clientID, serverID.Public, 1, time.Now())
	AddMACs(hs1.Message, serverID.Public, nil)
	AddMACs(hs2.Message, serverID.Public, nil)
	reply, _ := NewCookieChecker(serverID.Public).CreateReply(hs1.Message, "x")
	if _, err := ConsumeCookieReply(reply, hs2.Message, serverID.Public); err == nil {
		t.Fatal("cookie reply accepted for a different handshake message")
	}
}

func TestFragmentation(t *testing.T) {
	msg := make([]byte, InitiationSize)
	for i := range msg {
		msg[i] = byte(i * 7)
	}
	frags := Fragment(msg)
	if len(frags) != (InitiationSize+FragmentPayload-1)/FragmentPayload {
		t.Fatalf("got %d fragments", len(frags))
	}
	r := NewReassembler[string]()
	// Deliver out of order, with a duplicate, interleaved with another source.
	order := []int{3, 0, 0, 5, 1, 4}
	for _, i := range order {
		if _, done := r.Add("a", frags[i]); done {
			t.Fatal("completed early")
		}
		r.Add("b", frags[i])
	}
	got, done := r.Add("a", frags[2])
	if !done || !bytes.Equal(got, msg) {
		t.Fatal("reassembled message differs")
	}
}

func TestReassemblerBounded(t *testing.T) {
	r := NewReassembler[int]()
	for i := range maxReassemblies * 3 {
		f := Fragment(make([]byte, 2*FragmentPayload))[0]
		r.Add(i, f)
	}
	if n := len(r.partial); n > maxReassemblies {
		t.Fatalf("holding %d partial messages, limit is %d", n, maxReassemblies)
	}
}

func TestTimestampOrder(t *testing.T) {
	now := time.Now()
	a, b := NewTimestamp(now), NewTimestamp(now.Add(time.Nanosecond))
	if !b.After(a) || a.After(b) || a.After(a) {
		t.Fatal("timestamp ordering is wrong")
	}
}

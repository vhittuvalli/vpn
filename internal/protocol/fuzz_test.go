package protocol

import (
	"bytes"
	"testing"
	"time"
)

// Fuzz targets for everything that parses bytes from the network. Run one
// with, for example:
//
//	go test ./internal/protocol -run XXX -fuzz FuzzConsumeInitiation -fuzztime 1m
//
// Plain `go test` runs only the seed inputs.

func fuzzIdentities(f *testing.F) (server, client *Identity) {
	f.Helper()
	sk, err := GeneratePrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	ck, err := GeneratePrivateKey()
	if err != nil {
		f.Fatal(err)
	}
	return NewIdentity(sk), NewIdentity(ck)
}

// The server must reject any initiation except a real one from an allowed
// client, without panicking.
func FuzzConsumeInitiation(f *testing.F) {
	server, client := fuzzIdentities(f)
	hs, err := CreateInitiation(client, server.Public, 7, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	AddMACs(hs.Message, server.Public, nil)
	f.Add(hs.Message)
	f.Add([]byte{TypeInitiation})
	f.Add(make([]byte, InitiationSize))

	f.Fuzz(func(t *testing.T, msg []byte) {
		r, err := ConsumeInitiation(server, msg, func(k PublicKey) bool { return k == client.Public })
		if err != nil {
			return
		}
		if !bytes.Equal(msg, hs.Message) {
			t.Fatalf("accepted an initiation the client never sent")
		}
		if r.Peer != client.Public {
			t.Fatalf("accepted initiation names the wrong peer")
		}
	})
}

// The client must reject any response except the server's real one.
func FuzzConsumeResponse(f *testing.F) {
	server, client := fuzzIdentities(f)
	hs, err := CreateInitiation(client, server.Public, 7, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	r, err := ConsumeInitiation(server, hs.Message, func(PublicKey) bool { return true })
	if err != nil {
		f.Fatal(err)
	}
	_, resp, err := r.CreateResponse(server, 9)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(resp)
	f.Add(make([]byte, ResponseSize))

	f.Fuzz(func(t *testing.T, msg []byte) {
		if _, err := hs.ConsumeResponse(msg); err == nil && !bytes.Equal(msg, resp) {
			t.Fatalf("accepted a response the server never sent")
		}
	})
}

// Data messages: only ones sealed under the session key may open, each only
// once.
func FuzzSessionOpen(f *testing.F) {
	sender := newSession(1, 2, [32]byte{1}, [32]byte{2})
	sealed, err := sender.Seal([]byte("hello"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sealed)
	f.Add(make([]byte, DataHeaderSize+tagSize))

	f.Fuzz(func(t *testing.T, msg []byte) {
		receiver := newSession(2, 1, [32]byte{2}, [32]byte{1})
		pt, err := receiver.Open(msg)
		if err != nil {
			return
		}
		if !bytes.Equal(msg, sealed) || string(pt) != "hello" {
			t.Fatalf("opened a forged message: %x", msg)
		}
		if _, err := receiver.Open(msg); err == nil {
			t.Fatal("replay accepted")
		}
	})
}

// Fragments from the network must never panic, grow without bound, or
// produce a message larger than the fragment limits allow.
func FuzzReassembler(f *testing.F) {
	for _, frag := range Fragment(bytes.Repeat([]byte("x"), 2500)) {
		f.Add(frag)
	}
	f.Add([]byte{TypeFragment, 0, 1, 0, 1, 2, 3, 4, 'a'})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := NewReassembler[int]()
		// Treat the input as a stream of fragments, each prefixed with
		// its length, from a handful of sources.
		for i := 0; len(data) > 1; i++ {
			n := min(int(data[0])*8, len(data)-1)
			frag := data[1 : 1+n]
			data = data[1+n:]
			if msg, ok := r.Add(i%3, frag); ok && len(msg) > maxFragments*FragmentPayload {
				t.Fatalf("reassembled %d bytes, more than %d fragments can hold", len(msg), maxFragments)
			}
		}
		if len(r.partial) > maxReassemblies {
			t.Fatalf("%d partial messages held, limit %d", len(r.partial), maxReassemblies)
		}
	})
}

// Cookie replies are accepted only from the server, for the message sent.
func FuzzConsumeCookieReply(f *testing.F) {
	server, client := fuzzIdentities(f)
	hs, err := CreateInitiation(client, server.Public, 7, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	AddMACs(hs.Message, server.Public, nil)
	checker := NewCookieChecker(server.Public)
	reply, err := checker.CreateReply(hs.Message, "203.0.113.5:4000")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(reply)
	f.Add(make([]byte, CookieReplySize))

	f.Fuzz(func(t *testing.T, msg []byte) {
		if _, err := ConsumeCookieReply(msg, hs.Message, server.Public); err == nil && !bytes.Equal(msg, reply) {
			t.Fatalf("accepted a cookie reply the server never sent")
		}
	})
}

func FuzzReceiverIndex(f *testing.F) {
	f.Add([]byte{TypeData, 0, 0, 0, 1, 2, 3, 4})
	f.Add(make([]byte, ResponseSize))
	f.Fuzz(func(t *testing.T, msg []byte) {
		ReceiverIndex(msg)
	})
}

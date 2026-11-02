package main

import (
	"bytes"
	"encoding/binary"
	"image/png"
	"testing"
)

func TestIcons(t *testing.T) {
	for _, filled := range []bool{false, true} {
		img, err := png.Decode(bytes.NewReader(shieldTemplate(filled)))
		if err != nil || img.Bounds().Dx() != 36 {
			t.Fatalf("template icon: %v, %v", img, err)
		}
	}
	ico := shieldBadge(true)
	var header struct{ Reserved, Type, Count uint16 }
	binary.Read(bytes.NewReader(ico), binary.LittleEndian, &header)
	if header != (struct{ Reserved, Type, Count uint16 }{0, 1, 1}) {
		t.Fatalf("ico header %+v", header)
	}
	size := binary.LittleEndian.Uint32(ico[6+8:])
	offset := binary.LittleEndian.Uint32(ico[6+12:])
	img, err := png.Decode(bytes.NewReader(ico[offset : offset+size]))
	if err != nil || img.Bounds().Dx() != 32 || ico[6] != 32 {
		t.Fatalf("ico payload: %v, %v", img, err)
	}
	if bytes.Equal(shieldBadge(true), shieldBadge(false)) {
		t.Fatal("connected and off icons are the same")
	}
}

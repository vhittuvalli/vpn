package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"sync"
)

// Tray icons are drawn in code, so there are no image files to ship.

// inShield reports whether (x, y), in 0..1 coordinates, is inside a shield:
// a flat top, straight sides, then curving to a point at the bottom.
// inset shrinks it, for drawing outlines.
func inShield(x, y, inset float64) bool {
	l, r, top, bot := 0.2+inset, 0.8-inset, 0.1+inset, 0.92-inset*1.4
	if y < top || y > bot || x < l || x > r {
		return false
	}
	shoulder := top + (bot-top)*0.45
	if y <= shoulder {
		return true
	}
	t := (y - shoulder) / (bot - shoulder)
	half := (r - l) / 2 * (1 - t*t)
	return x >= 0.5-half && x <= 0.5+half
}

// render draws a size×size image with 4×4 supersampling; paint returns the
// color at a point in 0..1 coordinates (transparent for nothing).
func render(size int, paint func(x, y float64) color.NRGBA) []byte {
	const ss = 4
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					c := paint((float64(px)+(float64(sx)+0.5)/ss)/float64(size), (float64(py)+(float64(sy)+0.5)/ss)/float64(size))
					w := float64(c.A)
					r, g, b, a = r+float64(c.R)*w, g+float64(c.G)*w, b+float64(c.B)*w, a+w
				}
			}
			if a > 0 {
				img.SetNRGBA(px, py, color.NRGBA{uint8(r / a), uint8(g / a), uint8(b / a), uint8(a / (ss * ss))})
			}
		}
	}
	var buf bytes.Buffer
	png.Encode(&buf, img)
	return buf.Bytes()
}

var (
	iconMu    sync.Mutex
	iconCache = map[string][]byte{}
)

func cached(key string, draw func() []byte) []byte {
	iconMu.Lock()
	defer iconMu.Unlock()
	if b, ok := iconCache[key]; ok {
		return b
	}
	iconCache[key] = draw()
	return iconCache[key]
}

// shieldTemplate is the macOS menu bar icon: a black shield outline when
// off, filled when connected. As a template image, macOS tints it to match
// the menu bar.
func shieldTemplate(filled bool) []byte {
	key := "template-off"
	if filled {
		key = "template-on"
	}
	return cached(key, func() []byte {
		return render(36, func(x, y float64) color.NRGBA { // 18 pt at 2x
			if inShield(x, y, 0) && (filled || !inShield(x, y, 0.075)) {
				return color.NRGBA{0, 0, 0, 255}
			}
			return color.NRGBA{}
		})
	})
}

// shieldBadge is the Windows tray icon: a white shield on a rounded square,
// orange when connected and gray when off, readable on light and dark
// taskbars. It's an .ico, which Windows tray icons must be.
func shieldBadge(connected bool) []byte {
	key, bg := "badge-off", color.NRGBA{0x6b, 0x72, 0x80, 255}
	if connected {
		key, bg = "badge-on", color.NRGBA{0xd2, 0x63, 0x1a, 255}
	}
	return cached(key, func() []byte {
		pngData := render(32, func(x, y float64) color.NRGBA {
			if !inRoundedSquare(x, y, 0.02, 0.22) {
				return color.NRGBA{}
			}
			// The shield, scaled into the square.
			if inShield((x-0.5)/0.78+0.5, (y-0.5)/0.78+0.5, 0) {
				return color.NRGBA{255, 255, 255, 255}
			}
			return bg
		})
		return icoFromPNG(pngData, 32)
	})
}

func inRoundedSquare(x, y, inset, radius float64) bool {
	lo, hi := inset, 1-inset
	if x < lo || x > hi || y < lo || y > hi {
		return false
	}
	cx := min(max(x, lo+radius), hi-radius)
	cy := min(max(y, lo+radius), hi-radius)
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= radius*radius
}

// icoFromPNG wraps a square PNG in the .ico format, which since Windows
// Vista may carry PNG data directly.
func icoFromPNG(pngData []byte, size int) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, struct {
		Reserved, Type, Count uint16
	}{0, 1, 1})
	dim := uint8(size)
	if size >= 256 {
		dim = 0 // 0 means 256
	}
	binary.Write(&b, binary.LittleEndian, struct {
		Width, Height, Colors, Reserved uint8
		Planes, BitCount                uint16
		Size, Offset                    uint32
	}{dim, dim, 0, 0, 1, 32, uint32(len(pngData)), 6 + 16})
	b.Write(pngData)
	return b.Bytes()
}

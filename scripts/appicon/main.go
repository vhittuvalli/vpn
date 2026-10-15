// Command appicon draws the Mac app icon (a white shield on an orange
// rounded square) into an .iconset folder for iconutil.
//
//	go run ./scripts/appicon VPN.iconset && iconutil -c icns VPN.iconset
package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"math"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: appicon OUT.iconset")
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	for _, pt := range []int{16, 32, 128, 256, 512} {
		for _, scale := range []int{1, 2} {
			name := fmt.Sprintf("icon_%dx%d.png", pt, pt)
			if scale == 2 {
				name = fmt.Sprintf("icon_%dx%d@2x.png", pt, pt)
			}
			if err := write(filepath.Join(dir, name), pt*scale); err != nil {
				log.Fatal(err)
			}
		}
	}
}

func write(path string, size int) error {
	img := draw(size)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

var (
	top    = color.NRGBA{0xd2, 0x63, 0x1a, 0xff}
	bottom = color.NRGBA{0xa4, 0x44, 0x08, 0xff}
	white  = color.NRGBA{0xff, 0xff, 0xff, 0xff}
)

// draw renders the icon at size×size with 4×4 supersampling. Apple's grid
// puts the rounded square at 824/1024 of the canvas.
func draw(size int) *image.NRGBA {
	const ss = 4
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					if !inSquircle(x, y) {
						continue
					}
					c := lerp(top, bottom, (y-0.1)/0.8)
					if inShield(x, y) {
						c = white
					}
					r, g, b, a = r+float64(c.R), g+float64(c.G), b+float64(c.B), a+255
				}
			}
			n := float64(ss * ss)
			if a > 0 {
				k := 255 / a
				img.SetNRGBA(px, py, color.NRGBA{uint8(r * k), uint8(g * k), uint8(b * k), uint8(a / n)})
			}
		}
	}
	return img
}

func inSquircle(x, y float64) bool {
	const inset, radius = 100.0 / 1024, 185.0 / 1024
	l, t, r, b := inset, inset, 1-inset, 1-inset
	if x < l || x > r || y < t || y > b {
		return false
	}
	cx := math.Max(l+radius, math.Min(x, r-radius))
	cy := math.Max(t+radius, math.Min(y, b-radius))
	return (x-cx)*(x-cx)+(y-cy)*(y-cy) <= radius*radius
}

// inShield matches the menu bar icon's shape, scaled into the square.
func inShield(x, y float64) bool {
	l, r, t, b := 0.33, 0.67, 0.27, 0.77
	if y < t || y > b || x < l || x > r {
		return false
	}
	shoulder := t + (b-t)*0.45
	if y <= shoulder {
		return true
	}
	u := (y - shoulder) / (b - shoulder)
	half := (r - l) / 2 * (1 - u*u)
	return math.Abs(x-0.5) <= half
}

func lerp(a, b color.NRGBA, t float64) color.NRGBA {
	t = math.Max(0, math.Min(1, t))
	m := func(x, y uint8) uint8 { return uint8(float64(x) + (float64(y)-float64(x))*t) }
	return color.NRGBA{m(a.R, b.R), m(a.G, b.G), m(a.B, b.B), 255}
}

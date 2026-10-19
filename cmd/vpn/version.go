package main

import (
	"strconv"
	"strings"
)

// newerVersion reports whether release tag latest is newer than current,
// both like "v1.2.3" or "v1.2.3-rc1". A pre-release is older than the
// release it leads up to. Unparseable versions (such as "dev") never
// compare as newer.
func newerVersion(latest, current string) bool {
	l, lpre, ok1 := parseVersion(latest)
	c, cpre, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	switch {
	case lpre == cpre:
		return false
	case lpre == "":
		return true // release beats its pre-release
	case cpre == "":
		return false
	default:
		return lpre > cpre
	}
}

func parseVersion(v string) (nums [3]int, pre string, ok bool) {
	v, found := strings.CutPrefix(v, "v")
	if !found {
		return nums, "", false
	}
	v, pre, _ = strings.Cut(v, "-")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return nums, "", false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nums, "", false
		}
		nums[i] = n
	}
	return nums, pre, true
}

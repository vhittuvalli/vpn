package main

import "strings"

// parseDialogResult splits what the key prompt's AppleScript returns, the
// clicked button's name and then the typed text on the following lines.
func parseDialogResult(out string) (button, text string) {
	button, text, _ = strings.Cut(strings.TrimRight(out, "\n"), "\n")
	return button, strings.TrimSpace(text)
}

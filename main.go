package main

import explainbin "github.com/afterdarksys/osx-explain-a-bin/cmd/explain-bin"

// Version is stamped at build time with -ldflags "-X main.Version=...".
// The Makefile has always passed that flag; there was previously no symbol of
// this name for it to write to, so the value was silently discarded and the
// version came from a constant in the command definition instead.
var Version = "dev"

func main() {
	explainbin.SetVersion(Version)
	explainbin.Execute()
}

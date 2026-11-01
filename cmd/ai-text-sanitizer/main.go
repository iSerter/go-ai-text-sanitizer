// Command ai-text-sanitizer removes invisible Unicode watermarks, hidden
// payloads and LLM artifacts from text files or stdin.
package main

import "os"

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

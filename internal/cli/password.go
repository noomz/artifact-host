package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/noomz/artifact-host/internal/sites"
)

const passwordUsage = "usage: ah password set SITE_ID [--stdin] | ah password clear SITE_ID (URL and user token required)"

// cmdPassword has no flag for the password value, so it never reaches shell
// history or the process list.
func cmdPassword(args []string) int {
	if len(args) < 1 || (args[0] != "set" && args[0] != "clear") {
		fmt.Fprintln(os.Stderr, passwordUsage)
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("password "+action, flag.ContinueOnError)
	base := fs.String("url", os.Getenv("ARTIFACT_HOST_URL"), "server URL")
	token := fs.String("token", os.Getenv("ARTIFACT_HOST_TOKEN"), "user token")
	fromStdin := fs.Bool("stdin", false, "read the password from standard input")
	positional, err := parseInterspersed(fs, args[1:])
	if err != nil {
		return 2
	}
	if *base == "" || *token == "" || len(positional) != 1 || (action == "clear" && *fromStdin) {
		fmt.Fprintln(os.Stderr, passwordUsage)
		return 2
	}
	endpoint := strings.TrimRight(*base, "/") + "/v1/sites/" + url.PathEscape(positional[0]) + "/password"
	var req *http.Request
	if action == "clear" {
		req, err = http.NewRequest(http.MethodDelete, endpoint, nil)
	} else {
		var password string
		if *fromStdin {
			password, err = readPasswordStdin()
		} else {
			password, err = promptPassword()
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		var body []byte
		if body, err = json.Marshal(map[string]string{"password": password}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		req, err = http.NewRequest(http.MethodPut, endpoint, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+*token)
	return dump(req)
}

// parseInterspersed allows flags after positional arguments, which flag.Parse
// alone stops reading at.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// readPasswordStdin keeps every byte but one line ending. Reading past the limit
// is pointless, and leaves a value the server rejects as too long.
func readPasswordStdin() (string, error) {
	b, err := io.ReadAll(io.LimitReader(os.Stdin, sites.PasswordMaxBytes+3))
	if err != nil {
		return "", err
	}
	return trimLineEnding(string(b)), nil
}

func trimLineEnding(s string) string {
	return strings.TrimSuffix(strings.TrimSuffix(s, "\n"), "\r")
}

// promptPassword uses stty because the standard library cannot turn off echo. It
// refuses to read if echo stays on, rather than show the password.
func promptPassword() (string, error) {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return "", errors.New("password set needs a terminal or --stdin")
	}
	stty := func(arg string) error {
		c := exec.Command("stty", arg)
		c.Stdin = os.Stdin
		return c.Run()
	}
	if err := stty("-echo"); err != nil {
		return "", fmt.Errorf("cannot hide password input, use --stdin: %w", err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		if _, ok := <-signals; ok {
			_ = stty("echo")
			os.Exit(130)
		}
	}()
	defer func() {
		signal.Stop(signals)
		close(signals)
		_ = stty("echo")
	}()
	fmt.Fprint(os.Stderr, "Password: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Fprintln(os.Stderr)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return trimLineEnding(line), nil
}

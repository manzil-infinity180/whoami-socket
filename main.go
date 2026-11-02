// whoami-socket shows two ways a local server can answer "who is calling me?".
//
//	guess          the forgeable way: parent PID, process name, $PATH, own uid
//	serve --unix   the kernel way: peer credentials on a Unix domain socket
//	serve --tcp    the trap: the same getsockopt on a TCP socket
//	dial           a tiny client for serve
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "guess":
		guess()
	case "serve":
		if len(os.Args) != 4 {
			usage()
		}
		serve(os.Args[2], os.Args[3])
	case "dial":
		if len(os.Args) != 4 {
			usage()
		}
		dial(os.Args[2], os.Args[3])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  whoami guess
  whoami serve --unix /tmp/whoami.sock | --tcp 127.0.0.1:9999
  whoami dial  --unix /tmp/whoami.sock | --tcp 127.0.0.1:9999`)
	os.Exit(2)
}

// guess identifies "the agent" the way aflock v1 did: by looking at its own
// parent and its own surroundings. Nothing here comes from the caller.
func guess() {
	ppid := os.Getppid()
	parentCmd := argvOf(ppid)
	fmt.Println("== asking around (forgeable) ==")
	fmt.Printf("parent pid        %d            (os.Getppid)\n", ppid)
	fmt.Printf("parent command    %q   (ps: argv, chosen by the process)\n", parentCmd)
	fmt.Printf("parent is claude? %v\n", strings.Contains(parentCmd, "claude"))
	if p, err := exec.LookPath("claude"); err == nil {
		fmt.Printf("claude binary     %s   (first match on MY $PATH)\n", p)
		fmt.Printf("claude sha256     %s\n", short(digestPath(p)))
	} else {
		fmt.Println("claude binary     not on $PATH")
	}
	fmt.Printf("uid               %d            (os.Getuid: MY uid, not the caller's)\n", os.Getuid())
	fmt.Println()
	fmt.Println("== what the parent really is ==")
	exe, digest, err := exeOf(ppid)
	if err != nil {
		fmt.Println("exe lookup failed:", err)
		return
	}
	fmt.Printf("parent exe        %s\n", exe)
	fmt.Printf("parent sha256     %s\n", short(digest))
}

func serve(flag, addr string) {
	network := map[string]string{"--unix": "unix", "--tcp": "tcp"}[flag]
	if network == "" {
		usage()
	}
	if network == "unix" {
		_ = os.Remove(addr)
	}
	ln, err := net.Listen(network, addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen:", err)
		os.Exit(1)
	}
	if network == "unix" {
		// Only my uid may connect. The kernel check below is the real gate;
		// this just keeps other users from reaching it at all.
		_ = os.Chmod(addr, 0o600)
	}
	fmt.Printf("listening on %s %s (my pid %d, uid %d)\n\n", network, addr, os.Getpid(), os.Getuid())
	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "accept:", err)
			continue
		}
		handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	claim, _ := bufio.NewReader(conn).ReadString('\n')

	fmt.Println("== new connection ==")
	fmt.Printf("peer says         %q   (bytes it chose to send)\n", strings.TrimSpace(claim))

	cred, err := peerCred(conn)
	if err != nil {
		fmt.Printf("kernel creds      ERROR: %v\n\n", err)
		fmt.Fprintf(conn, "no kernel credentials: %v\n", err)
		return
	}
	fmt.Printf("kernel creds      pid=%d uid=%d gid=%d   (%s)\n", cred.PID, cred.UID, cred.GID, cred.Source)
	if cred.PID <= 0 {
		fmt.Printf("                  pid %d is not a process: treat as UNKNOWN, never as a user\n\n", cred.PID)
		fmt.Fprintln(conn, "kernel gave no usable peer")
		return
	}
	if cred.UID != uint32(os.Getuid()) {
		fmt.Printf("                  uid mismatch: refusing\n\n")
		fmt.Fprintln(conn, "refused: different uid")
		return
	}
	fmt.Printf("peer argv         %q   (still the process's own words)\n", argvOf(cred.PID))
	exe, digest, err := exeOf(cred.PID)
	if err != nil {
		fmt.Printf("peer exe          ERROR: %v\n\n", err)
		return
	}
	fmt.Printf("peer exe          %s\n", exe)
	fmt.Printf("peer sha256       %s\n\n", short(digest))
	fmt.Fprintf(conn, "you are pid %d uid %d running %s\n", cred.PID, cred.UID, exe)
}

func dial(flag, addr string) {
	network := map[string]string{"--unix": "unix", "--tcp": "tcp"}[flag]
	if network == "" {
		usage()
	}
	conn, err := net.Dial(network, addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer conn.Close()
	// A client can claim anything. The server prints this next to what the
	// kernel says so the difference is visible.
	fmt.Fprintln(conn, "hello, I am claude-code 2.1.0")
	reply, _ := io.ReadAll(conn)
	fmt.Print(string(reply))
}

func digestPath(path string) string {
	f, err := os.Open(path) //nolint:gosec // demo: path is a resolved executable
	if err != nil {
		return ""
	}
	defer f.Close()
	return hashReader(f)
}

func hashReader(r io.Reader) string {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func short(digest string) string {
	if len(digest) < 16 {
		return digest
	}
	return digest[:16] + "…"
}

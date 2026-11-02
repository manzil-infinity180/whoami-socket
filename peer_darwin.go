//go:build darwin

package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type cred struct {
	PID    int
	UID    uint32
	GID    uint32
	Source string
}

// peerCred asks the kernel who is on the other end. macOS needs two calls:
// LOCAL_PEERPID for the pid and LOCAL_PEERCRED (struct xucred) for uid and
// groups. SPIRE's peertracker (uds_bsd.go) makes only the first call and
// looks the uid up from the pid afterwards.
func peerCred(conn net.Conn) (cred, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return cred{}, errors.New("not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return cred{}, err
	}
	var (
		pid           int
		xu            *unix.Xucred
		pidErr, xuErr error
	)
	if err := raw.Control(func(fd uintptr) {
		pid, pidErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
		xu, xuErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return cred{}, err
	}
	if pidErr != nil {
		return cred{}, fmt.Errorf("LOCAL_PEERPID: %w", pidErr)
	}
	if xuErr != nil {
		return cred{}, fmt.Errorf("LOCAL_PEERCRED: %w", xuErr)
	}
	c := cred{PID: pid, UID: xu.Uid, Source: "LOCAL_PEERPID + LOCAL_PEERCRED"}
	if xu.Ngroups > 0 {
		c.GID = xu.Groups[0]
	}
	return c, nil
}

// exeOf finds the peer's executable with lsof (libproc underneath) and
// hashes it. macOS has no /proc/<pid>/exe to pin, so a signal-0 probe
// afterwards only confirms the pid is still alive.
func exeOf(pid int) (string, string, error) {
	out, err := exec.Command("/usr/sbin/lsof", "-p", strconv.Itoa(pid), "-Fn").Output() //nolint:gosec // pid from the kernel
	if err != nil {
		return "", "", fmt.Errorf("lsof: %w", err)
	}
	path := ""
	atTxt := false
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "ftxt":
			atTxt = true
		case strings.HasPrefix(line, "f"):
			atTxt = false
		case atTxt && strings.HasPrefix(line, "n") && path == "":
			path = line[1:]
		}
	}
	if path == "" {
		return "", "", fmt.Errorf("no executable mapping for pid %d", pid)
	}
	f, err := os.Open(path) //nolint:gosec // path resolved by libproc
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	digest := hashReader(f)
	if err := syscall.Kill(pid, 0); err != nil {
		return "", "", fmt.Errorf("pid %d exited while we looked: %w", pid, err)
	}
	return path, digest, nil
}

// argvOf returns what the process says its command line is.
func argvOf(pid int) string {
	out, err := exec.Command("ps", "-o", "command=", "-p", strconv.Itoa(pid)).Output() //nolint:gosec // demo
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

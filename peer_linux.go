//go:build linux

package main

import (
	"errors"
	"fmt"
	"net"
	"os"
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

// peerCred asks the kernel who is on the other end. On Linux one call,
// SO_PEERCRED, returns pid, uid and gid as they were at connect() time.
// This is the same call SPIRE's peertracker makes (uds_linux.go).
func peerCred(conn net.Conn) (cred, error) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return cred{}, errors.New("not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return cred{}, err
	}
	var uc *unix.Ucred
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		uc, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return cred{}, err
	}
	if sockErr != nil {
		return cred{}, fmt.Errorf("SO_PEERCRED: %w", sockErr)
	}
	// On a TCP socket this call does not fail. It returns pid 0 and
	// uid/gid 4294967295. The caller must not treat that as an identity.
	return cred{PID: int(uc.Pid), UID: uc.Uid, GID: uc.Gid, Source: "SO_PEERCRED"}, nil
}

// exeOf hashes the peer's executable through /proc/<pid>/exe. Opening the
// link pins the inode, and the start time is read before and after so a
// recycled PID is caught.
func exeOf(pid int) (string, string, error) {
	t1, err := startTime(pid)
	if err != nil {
		return "", "", err
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	t2, err := startTime(pid)
	if err != nil {
		return "", "", err
	}
	if t1 != t2 {
		return "", "", fmt.Errorf("pid %d was recycled while we looked", pid)
	}
	// Resolve the path through OUR fd so it names the same inode we hash.
	path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd()))
	return path, hashReader(f), nil
}

// startTime is field 22 of /proc/<pid>/stat. The command name in field 2
// can contain spaces and ')', so split after the last ')'.
func startTime(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(data), ')')
	fields := strings.Fields(string(data[end+1:]))
	if end < 0 || len(fields) < 20 {
		return "", fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	return fields[19], nil
}

// argvOf returns what the process says its command line is.
func argvOf(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
}

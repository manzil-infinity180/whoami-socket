# whoami-socket

A local server wants to know who is calling it. This shows the two ways to find out, and why only one of them can be trusted.

```
go build -o whoami .
./scripts/demo.sh          # the three scenes, one key press each
```

| Command | What it shows |
|---|---|
| `whoami guess` | The forgeable way: parent PID, `ps` command line, `$PATH` lookup, own uid. |
| `whoami serve --unix /tmp/whoami.sock` | The kernel way: peer pid/uid/gid from the socket, then the peer's real executable and its SHA-256. |
| `whoami serve --tcp 127.0.0.1:9999` | The trap: the same call on TCP gives you nothing usable. |
| `whoami dial --unix … \| --tcp …` | A client that claims to be `claude-code 2.1.0`. |

## How the kernel answers

| OS | Call | Gives |
|---|---|---|
| Linux | `getsockopt(SOL_SOCKET, SO_PEERCRED)` | pid, uid, gid in one `struct ucred` |
| macOS | `getsockopt(SOL_LOCAL, LOCAL_PEERPID)` | pid |
| macOS | `getsockopt(SOL_LOCAL, LOCAL_PEERCRED)` | uid + groups (`struct xucred`, no pid) |

The kernel stores these on the socket at `connect()`. The client never sends them, so it cannot lie about them. What it *can* still lie about is its argv, its environment and the bytes it sends.

A PID is only a number, so after getting it:

1. Linux: read the start time, open `/proc/<pid>/exe`, read the start time again. Different start time means the PID was recycled. Hash through the open file, so the digest is the binary that was running.
2. macOS: no `/proc`; find the executable with `lsof` (libproc), hash it, then `kill(pid, 0)`. That only proves *some* process with that PID exists; a recycled PID passes too. Stronger: watch for exit with kqueue `EVFILT_PROC` (what SPIRE does), or read `LOCAL_PEERTOKEN` and compare `audit_token_to_pidversion`.

Both checks narrow the window rather than close it: a PID recycled before the first look gets through. Linux 6.5+ `SO_PEERPIDFD` closes it.

## Output from a real run (macOS)

```
== new connection ==
peer says         "hello, I am claude-code 2.1.0"   (bytes it chose to send)
kernel creds      pid=60764 uid=501 gid=20   (LOCAL_PEERPID + LOCAL_PEERCRED)
peer argv         "claude dial --unix /tmp/whoami.sock"   (still the process's own words)
peer exe          /Users/rahulxf/work-dir/whoami-socket/whoami
peer sha256       ea5f65b6d1760b9d…
```

TCP on macOS: `LOCAL_PEERPID: protocol not available`.

TCP on Linux (Rocky Linux 9.8, kernel 5.14): `SO_PEERCRED` *succeeds* and returns nothing usable, which is why `serve` treats pid ≤ 0 as "unknown" instead of a user:

```
kernel creds      pid=0 uid=4294967295 gid=4294967295   (SO_PEERCRED)
                  pid 0 is not a process: treat as UNKNOWN, never as a user
```

## Credits

The socket calls follow SPIRE's `pkg/common/peertracker` (`uds_linux.go`, `uds_bsd.go`) and the start-time check follows its Linux watcher. aflock's `internal/identity/peercred` uses the same pattern.

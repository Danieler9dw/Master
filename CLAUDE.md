# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

Per the README, the intended purpose of this repository is:

> An EAP-AKA protocol and TACACS+ server

A TACACS+ daemon (RFC 8907) exists under `src/`, covering authentication,
authorization, and accounting. EAP-AKA is not implemented yet.

## Build, lint, test, run

Plain C11 + POSIX (sockets, fork), no external dependencies, no package manager.

```sh
make            # builds bin/tacacsd from src/*.c into build/*.o
make test       # builds and runs tests/test_md5 and tests/test_packet
make clean      # removes build/ and bin/
```

There is no separate lint target; `make` itself builds with
`-Wall -Wextra -Wpedantic` and warnings should be treated as errors to fix.

To run a single test binary directly (each `main()` returns non-zero and
prints `FAIL: ...` lines on failure):

```sh
make bin/test_md5 && ./bin/test_md5
make bin/test_packet && ./bin/test_packet
```

To run the server against a local client, copy `tacacs.conf.example` to
`tacacs.conf`, edit the `key` and `user` lines, and run
`./bin/tacacsd tacacs.conf` (binding to the default port 49 requires root;
set `port = ` in the config to use an unprivileged port instead).

## Architecture

The wire protocol (packet framing, encryption) is decoupled from the three
TACACS+ services (authentication, authorization, accounting), which are in
turn decoupled from connection/process handling:

- `src/md5.c` / `md5.h` — standalone RFC 1321 MD5, used only to derive the
  TACACS+ body obfuscation pad (TACACS+ is not otherwise cryptographically
  secure and is expected to run over a trusted/tunneled network).
- `src/packet.c` / `packet.h` — the 12-byte header (encode/decode) and
  `tac_crypt`, the MD5 pseudo-pad XOR obfuscation from RFC 8907 §4.5. Pure
  functions, no I/O; this is what `tests/test_packet.c` exercises directly.
- `src/io.c` / `io.h` — `tac_read_packet` / `tac_write_packet` sit on top of
  `packet.h` and do the actual `read`/`write` on a connected socket,
  including decrypting/encrypting the body. Every service handler goes
  through these instead of touching the socket directly.
- `src/config.c` / `config.h` — loads the shared secret key, listen port,
  and a flat user/password list from a small custom config format (see
  `tacacs.conf.example`). Deliberately not the real `tac_plus.conf` grammar.
- `src/authen.c` / `authen.h` — the only stateful, multi-packet service:
  drives the ASCII-login START/CONTINUE/REPLY exchange (RFC 8907 §5),
  prompting for username and/or password as needed and checking them
  against `config.h`'s user list.
- `src/author.c` / `src/acct.c` — authorization and accounting are both
  single REQUEST/RESPONSE exchanges (RFC 8907 §6, §7), so unlike `authen.c`
  they don't need to read further packets themselves. Authorization grants
  `PASS_ADD` (no extra args) to any known user and denies everyone else;
  accounting logs the request and always replies `SUCCESS`.
- `src/server.c` / `server.h` — the TCP accept loop. Forks one child per
  connection; each child loops reading packets via `io.h` and dispatching
  by `tac_header_t.type` to `authen`/`author`/`acct`, until the connection
  closes.
- `src/main.c` — loads the config file named on argv (default
  `tacacs.conf`) and calls into `server.h`.

Nothing here implements PAP/CHAP authentication, single-connect mode, or
persistent accounting storage — those would be the natural next additions
if the TACACS+ side needs to grow further before EAP-AKA work begins.

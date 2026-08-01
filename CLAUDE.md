# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

Per the README, the intended purpose of this repository is:

> An EAP-AKA protocol and TACACS+ server

A TACACS+ daemon (RFC 8907) exists under `src/`, covering authentication,
authorization, and accounting.

EAP-AKA' work has started: generic EAP packet framing (RFC 3748) and the
Type/Length/Value attribute container shared by EAP-SIM/AKA/AKA' are
implemented. The EAP-AKA' method itself (subtype dispatch, the specific
AT_* attribute type numbers, AUTN/RES validation, and the RFC 9048 key
derivation) is **not** implemented yet — see "EAP-AKA' status" below
before adding to it.

## Build, lint, test, run

Plain C11 + POSIX (sockets, fork), no external dependencies, no package manager.

```sh
make            # builds bin/tacacsd from src/*.c into build/*.o
make test       # builds and runs every tests/test_*.c binary
make clean      # removes build/ and bin/
```

There is no separate lint target; `make` itself builds with
`-Wall -Wextra -Wpedantic` and warnings should be treated as errors to fix.

To run a single test binary directly (each `main()` returns non-zero and
prints `FAIL: ...` lines on failure):

```sh
make bin/test_md5 && ./bin/test_md5
make bin/test_packet && ./bin/test_packet
make bin/test_eap && ./bin/test_eap
make bin/test_eap_attr && ./bin/test_eap_attr
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
if the TACACS+ side needs to grow further.

EAP-AKA' pieces so far, deliberately generic (no EAP-AKA'-specific numbers
baked in yet):

- `src/eap.c` / `eap.h` — EAP packet framing per RFC 3748 §4: the
  Code/Identifier/Length/Type header plus Request/Response/Success/Failure
  encode/decode helpers. Transport- and method-agnostic.
- `src/eap_attr.c` / `eap_attr.h` — the Type/Length/Value attribute
  container shared by EAP-SIM (RFC 4186 §8.1), EAP-AKA, and EAP-AKA': an
  iterator for decoding a packed attribute list and an append helper for
  encoding one, including the length-in-4-byte-words framing and zero
  padding. Only knows the generic container and the skippable-if-type>=128
  convention — no specific attribute type numbers (AT_RAND, AT_MAC, etc.).

## EAP-AKA' status

This environment's network policy blocks outbound access to
`rfc-editor.org`/`ietf.org` (proxy returns 403), so the RFC 9048 text
could not be fetched to verify byte-level details while implementing
this. Rather than guess at security-critical constants from memory, the
following were deliberately left out of `src/eap.c`/`src/eap_attr.c` and
still need to be added, ideally cross-checked against the actual RFC text
(RFC 9048, plus RFC 4187 for base EAP-AKA and RFC 4186 §8.1 for the
attribute format it reuses) rather than recollection:

- The EAP-AKA' subtype values (Challenge, Authentication-Reject,
  Synchronization-Failure, Identity, Notification, Reauthentication,
  Client-Error) and the subtype dispatch/state machine built on top of
  `eap.h`.
- The specific attribute type numbers (AT_RAND, AT_AUTN, AT_RES, AT_AUTS,
  AT_MAC, AT_KDF, AT_KDF_INPUT, AT_CHECKCODE, ...) and each one's internal
  sub-fields, built on top of `eap_attr.h`.
- The AT_MAC computation (HMAC-SHA-256 truncated to 128 bits over the EAP
  packet with the MAC field zeroed) and verification.
- The CK'/IK' derivation from CK/IK and the access network identity, and
  the PRF'-based derivation of MK, K_encr, K_aut, K_re, MSK, and EMSK.
- The pluggable AKA algorithm interface (computing AUTN/RES/CK/IK/AK, and
  AUTS for resynchronization, from a subscriber key + RAND + SQN + AMF)
  and a placeholder/test-vector implementation — real Milenage (3GPP TS
  35.206) is out of scope for now.

If you have network access to fetch the RFC text, or the user provides
it, verify against that directly instead of continuing from memory.

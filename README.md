# Master
This is an EAP-AKA protocol and TACACS+ server

## Status

A TACACS+ daemon (`tacacsd`) implementing RFC 8907 is under `src/`:
authentication (ASCII login), authorization, and accounting, over a
forking TCP server.

EAP-AKA' work has started: generic EAP packet framing and the
Type/Length/Value attribute container it shares with EAP-SIM/AKA are
implemented. The EAP-AKA' method itself (subtypes, specific attributes,
and key derivation) is not implemented yet — see `CLAUDE.md` for why.

## Building and running

```sh
make            # builds bin/tacacsd
make test       # builds and runs the unit tests
cp tacacs.conf.example tacacs.conf   # edit the key/users to taste
./bin/tacacsd tacacs.conf            # defaults to port 49 (needs root); override with 'port =' in the config
```

See `CLAUDE.md` for architecture details.

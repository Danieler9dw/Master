# Master
This is an EAP-AKA protocol and TACACS+ server

## Status

A TACACS+ daemon (`tacacsd`) implementing RFC 8907 is under `src/`:
authentication (ASCII login), authorization, and accounting, over a
forking TCP server. EAP-AKA is not implemented yet.

## Building and running

```sh
make            # builds bin/tacacsd
make test       # builds and runs the unit tests
cp tacacs.conf.example tacacs.conf   # edit the key/users to taste
./bin/tacacsd tacacs.conf            # defaults to port 49 (needs root); override with 'port =' in the config
```

See `CLAUDE.md` for architecture details.

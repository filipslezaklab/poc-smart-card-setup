# Automatic OpenPGP Smart Card rust setup (poc)

Made to configure openPGP smart card for use with rust programming language only, without 3rd party dependencies like `gpg`.

## What does this do

- Checks if smart card supports RSA4096
- Makes primary RSA key with 2 sub-keys
- Exports primary key's public PGP key into `public.asc`
- Exports authorization public key as OpenSSH formatted data into `ssh.asc`
- Imports 2 sub-keys and primary key into the card Authorization, Decryption and Signing slots
- Sets example metadata

## How to run

Use rust `cargo run -r` command with ONE with fresh wiped out smart card preset, if more then one is detected, program will fail.

### How to prepare yubikey

Use `ykman` CLI program with command:

```bash
ykman openpgp reset
```

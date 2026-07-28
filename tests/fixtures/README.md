# Test key fixtures

**These are throwaway keys generated for the test suite. They are not secret, are
not used to access anything, and must never be installed anywhere.** They exist so
the PPK and OpenSSH decode paths are tested against files a real `puttygen` and
`ssh-keygen` produced, rather than against hand-written approximations.

The passphrase for every encrypted fixture is `hunter2`.

| File | Format | Encryption |
| ---- | ------ | ---------- |
| `ed25519_v3_plain.ppk`  | PuTTY v3 | none |
| `ed25519_v3_locked.ppk` | PuTTY v3 | aes256-cbc, Argon2 KDF |
| `rsa_v2_locked.ppk`     | PuTTY v2 | aes256-cbc |
| `openssh_ed25519_locked` | OpenSSH | aes256-ctr, bcrypt KDF |

Regenerate with:

```sh
: > /tmp/empty && printf 'hunter2' > /tmp/pp
puttygen -t ed25519 -o ed25519_v3_plain.ppk  -O private --ppk-param version=3 --new-passphrase /tmp/empty
puttygen -t ed25519 -o ed25519_v3_locked.ppk -O private --ppk-param version=3 --new-passphrase /tmp/pp
puttygen -t rsa -b 2048 -o rsa_v2_locked.ppk -O private --ppk-param version=2 --new-passphrase /tmp/pp
ssh-keygen -t ed25519 -N hunter2 -f openssh_ed25519_locked -q && rm openssh_ed25519_locked.pub
rm /tmp/empty /tmp/pp
```

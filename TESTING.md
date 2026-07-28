# Testing luvienne

## Automated

```sh
cargo test                          # 244 on macOS, 239 on Linux, + 1 ignored, ~3s (mostly Argon2 in the PPK fixtures)
cargo clippy --all-targets -- -D warnings
```

Rendering is asserted against ratatui's `TestBackend` buffer, so the UI is covered
without a terminal. Tests that save an inventory write to a temp path — the suite
must never be able to reach the real `hosts.toml`, so `App` takes its path
explicitly rather than deriving it. Key loading is covered against real `puttygen` / `ssh-keygen`
output in `tests/fixtures/`.

One test is `#[ignore]`d: the Keychain round trip writes to the developer's own
login keychain and can raise an access dialog, so it would hang CI.

```sh
cargo test a_stored_passphrase -- --ignored
```

The rest of the caching logic is tested through `orphaned_key_ids`, which is the
rule with the I/O lifted out precisely so the suite never touches a keychain.

## On Linux

Development happens on macOS, so Linux needs checking deliberately. A container
does it without installing a toolchain anywhere:

```sh
docker run --rm -v "$PWD:/src:ro" -w /src -e CARGO_TARGET_DIR=/tmp/target rust:1-slim \
  sh -c 'apt-get update -qq && apt-get install -y -qq build-essential cmake perl &&
         cargo test && cargo clippy --all-targets -- -D warnings'
```

`build-essential`, `cmake` and `perl` are for `aws-lc-sys`, a russh dependency
that builds C. That build script is also why **cross-compiling from macOS does
not work out of the box** — `cargo check --target aarch64-unknown-linux-gnu`
fails in it without a cross C toolchain, so a container is the short path.

`clippy -- -D warnings` is expected to pass on both platforms, and the keystore
is where it stops doing so: every `KeystoreError` variant is dead on the
platform that cannot produce it, so each carries a `cfg_attr` `allow` for the
*other* side. Adding a macOS-only item without one breaks the Linux build.

To drive the real TUI there, mount a config and a key and use the pty driver —
this exercises the parts most likely to be platform-specific (raw mode,
`ttyname`, `TIOCGWINSZ`, the terminal handoff):

```sh
docker run --rm -v "$PWD:/src:ro" -v "$CFG:/cfg/luvienne" -v "$HOMEDIR:/root" -w /src \
  -e CARGO_TARGET_DIR=/tmp/target -e XDG_CONFIG_HOME=/cfg -e HOME=/root \
  -e TERM=xterm-256color rust:1-slim \
  sh -c '... && python3 /src/scripts/drive_tui.py /tmp/target/debug/luvienne \
           "2:\\r" "6:uname -sm\\n" "4:" "1:exit\\n" "3:q"'
```

Put a `known_hosts` in the mounted home (`ssh-keyscan -H host >` it) or the
first connect stops on the host key prompt and nothing else runs.

## Against a real server

You need something to SSH into. A throwaway container is the least invasive option
— no `sudo`, no system settings, and you can delete it afterwards.

### 1. Start a test sshd

```sh
mkdir -p /tmp/lv-sshd
puttygen tests/fixtures/ed25519_v3_plain.ppk -O public-openssh \
  -o /tmp/lv-sshd/authorized_keys

cat > /tmp/lv-sshd/Dockerfile <<'EOF'
FROM alpine:latest
RUN apk add --no-cache openssh-server && ssh-keygen -A && adduser -D -s /bin/sh tester
RUN mkdir -p /home/tester/.ssh
COPY authorized_keys /home/tester/.ssh/authorized_keys
RUN chown -R tester:tester /home/tester/.ssh && chmod 700 /home/tester/.ssh \
 && chmod 600 /home/tester/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd","-D","-e"]
EOF

docker build -t luvienne-testsshd /tmp/lv-sshd
docker run -d --name luvienne-testsshd -p 2222:22 luvienne-testsshd
```

Sanity-check it with the stock client before blaming this app:

```sh
puttygen tests/fixtures/ed25519_v3_plain.ppk -O private-openssh -o /tmp/lv_key
chmod 600 /tmp/lv_key
ssh -i /tmp/lv_key -p 2222 tester@localhost 'echo ok'
```

### 2. Add the host

Press `a` in the app and fill in the form — `tab` moves between fields, `←/→` or
space changes the auth method, `^O` on the key path field opens a file browser,
`enter` saves. `e` edits the selected host and `d`
deletes it. Everything is written back to `hosts.toml`.

Or write it by hand — both still work. `~/.config/luvienne/hosts.toml`:

```toml
[[host]]
name = "docker-test"
address = "127.0.0.1"
port = 2222
user = "tester"
tags = ["lab"]
auth = { method = "key", path = "/absolute/path/to/tests/fixtures/ed25519_v3_plain.ppk" }
```

Swap in `ed25519_v3_locked.ppk` to exercise the passphrase prompt (`hunter2`), or
drop the `auth` line entirely to test agent auth after `ssh-add`.

### Testing password and keyboard-interactive

`auth = { method = "password" }` covers both. To exercise each, reconfigure the
container:

```sh
# password method
docker exec luvienne-testsshd sh -c \
  "echo 'tester:swordfish' | chpasswd; \
   sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config; \
   kill -HUP 1"
```

Keyboard-interactive needs a PAM-backed sshd. Alpine's stock `openssh-server`
advertises the method but has no backend, so it *always* fails — if you see
"keyboard-interactive authentication failed" against a plain container, that is
the server, not the client:

```sh
docker exec luvienne-testsshd apk add --no-cache openssh-server-pam linux-pam
docker commit luvienne-testsshd luvienne-pam
docker rm -f luvienne-testsshd
docker run -d --name luvienne-pam -p 2222:22 luvienne-pam \
  /usr/sbin/sshd.pam -D -e -o UsePAM=yes \
  -o PasswordAuthentication=no -o KbdInteractiveAuthentication=yes
```

With `PasswordAuthentication=no`, the client's method probe should send it
straight to keyboard-interactive — you should be asked for a secret exactly
once, with the server's own `Password` label rather than wording of ours.

### 3. Run it

```sh
cargo run
```

Enter connects; `ctrl-]` detaches and leaves the session running, with `●` in the
host list and `↵` to resume it where you left off. First connection prompts for the host key — check the fingerprint
against `docker exec luvienne-testsshd ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`
before accepting. `exit` in the shell returns you to the host list.

### 4. Clean up

```sh
docker rm -f luvienne-testsshd
ssh-keygen -R '[127.0.0.1]:2222'     # the app adds this on accept
```

### Testing passphrase caching

Caching happens while the key is being decrypted, which is *before* the key is
offered to the server — so the whole feature can be exercised against a host
that will reject the key anyway. Point a host at an encrypted fixture key, set
`cache_passphrase = true`, and let authentication fail.

Assert against the keychain, not against the screen. The app repaints only what
changed, so a progress message may not survive to the final frame, and "no
prompt appeared" is far easier to read from a state change than from a diff:

```sh
security find-generic-password -s luvienne          # what is stored
security delete-generic-password -s luvienne -a "key:/path/to/key"
```

Four runs cover it, each with a signal that differs between working and broken:

| run | keys sent | working looks like |
| --- | --- | --- |
| first connect | passphrase, `↵` | a keychain item appears |
| second connect | nothing | no passphrase prompt at all |
| a host without the opt-in, same key file | nothing | it prompts regardless |
| after replacing the file at that path | nothing | prompts, and the item is gone |
| after replacing it with an *unencrypted* key | nothing | connects, and the item is gone |

That last row is the one with no unit test behind it — the branch lives inside
`load_key_interactive`, which needs a server and a channel — so it is worth
running by hand after touching that function.

Do **not** seed the entry with `security add-generic-password` to fake a stale
one. An item created that way carries an ACL the app cannot read through, so the
app never gets as far as the stale-entry branch and falls straight to a prompt —
which looks exactly like the branch failing. Let the app store it, then swap in a
key with a different passphrase (`ssh-keygen -t ed25519 -N other -f newkey`).

### Testing port forwards

The only convincing test is carrying real traffic to somewhere otherwise
unreachable, so each direction needs a **control** proving the target cannot be
reached without the tunnel. Without that, a forward that silently did nothing
and a working one look identical.

Local (`-L`) — serve something on the server's loopback and fetch it here:

```sh
ssh you@server 'mkdir -p /tmp/lvfwd && echo HELLO > /tmp/lvfwd/proof.txt &&
  cd /tmp/lvfwd && (nohup python3 -m http.server 18080 --bind 127.0.0.1 &)'
nc -z -G 2 server 18080 && echo "REACHABLE — the control failed"   # must fail
# forwards = [{ direction = "local", listen_port = 18081, to_host = "127.0.0.1", to_port = 18080 }]
curl -s http://127.0.0.1:18081/proof.txt                            # HELLO
```

Remote (`-R`) — serve something on *this* machine's loopback and have the
server fetch it from its own:

```sh
# forwards = [{ direction = "remote", listen_port = 18091, to_host = "127.0.0.1", to_port = 18090 }]
ssh you@server 'python3 -c "import urllib.request;
  print(urllib.request.urlopen(\"http://127.0.0.1:18091/back.txt\").read())"'
```

Three things that will mislead you:

- **`SSH_AUTH_SOCK` does not reach the driven binary**, so a host configured for
  agent auth fails with "agent authentication failed" and no forward is ever
  raised. It looks exactly like a broken forward. Point the test host at a key
  file instead.
- **Probing the port after the app exits proves nothing** — process death closes
  it either way. To test teardown, end the session from inside (`exit`) and probe
  while the app is *still running*. Verified by mutation: with the abort removed
  the port stays open, with it the port closes.
- Run the fetch *while detached* as well as attached. A forward that only works
  while attached is useless, since staying attached is what you detached to avoid.

## Driving the TUI headlessly

`scripts/drive_tui.py` runs the binary on a real pty, sets a window size, sends
timed keystrokes, and prints what was drawn with escape sequences stripped.

```sh
python3 scripts/drive_tui.py ./target/debug/luvienne \
  "1.5:\r" "3:y" "5:echo HELLO\n" "3:exit\n" "3:q"
```

Each argument is `delay_seconds:keys`. Use it to reproduce a sequence without
typing it by hand.

**Recreate the fixture config before every driven run.** Stray keystrokes land in
the host list, where `d`/`y` deletes and `i`/`y` imports — a run that fails early
will rewrite the very config the next run depends on, and you will chase a bug in
the app that is actually a corrupted fixture. This has caused three false
diagnoses so far.

Three things that will waste your time if you don't know them:

- **`script -q /dev/null ./binary` does not work.** Keystrokes piped into it never
  reach the app, and the pty it allocates reports no window size, so ratatui draws
  empty frames. Use the pty driver.
- **Assertions on rendered output give false negatives.** The app only repaints
  what changed, so a value drawn once never reappears in the capture. Assert on the
  status line or the config file, not on whether a marker is present in the frames.
- **Nothing answers cursor-position queries under automation.** A real terminal
  replies to `ESC[6n`; a harness does not. The session-resume path was written to
  avoid that query for this reason — if you add a call that needs it, it will hang
  for ~2s and then fail only under automation.

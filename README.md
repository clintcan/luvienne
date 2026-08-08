# luvienne

A keyboard-driven SSH connection manager for the terminal, written in Rust.

It exists to make a large, messy set of hosts feel organised. Browse by
category, filter as you type, press enter. No `~/.ssh/config` archaeology and no
hunting for which key goes with which box.

```
╭ luvienne ────────────────────────────────────────────────────────────────────────────────────────────╮
│  press / to filter, ? for help                                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭ categories ────────╮╭ hosts (12) ────────────────────────────────────────────────────────────────────╮
│  all hosts         ││  name         destination                 auth       tags                      │
│  build 1           ││  app-01       deploy@10.20.0.11:22        agent      prod web                  │
│  db 3              ││  app-02       deploy@10.20.0.12:22        agent      prod web                  │
│  lab 1             ││● db-primary   postgres@10.20.1.5:22       key        prod db                   │
│  legacy 1          ││  db-replica   postgres@10.20.1.6:22       key        prod db                   │
│  obs 2             ││  bastion-eu   jump@bastion.eu.example.net agent      prod                      │
│  prod 7            ││  staging-app  (ask)@10.30.0.4:22          agent      staging web               │
│  staging 2         ││  staging-db   postgres@10.30.1.4:22       agent      staging db                │
│  web 3             ││  legacy-win   administrator@10.40.0.9:22  key        legacy                    │
│                    ││  build-runner ci@10.50.0.2:22             agent      build                     │
│                    ││  metrics      grafana@10.20.2.8:22        agent      prod obs                  │
│                    ││  logs         loki@10.20.2.9:22           agent      prod obs                  │
│                    ││  sandbox      (ask)@10.60.0.1:22          password   lab                       │
│                    ││                                                                                │
╰────────────────────╯╰────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   k/↑ move up   j/↓ move down   ↵ connect   / filter   t cycle tag   esc cancel / clear
```

The `●` marks a session that is still running: `Ctrl-]` detaches from a shell and
leaves it alive, and `↵` on a marked host drops you back into it where you left
off. `(ask)` means no username is stored and you will be asked at connect time.

Hosts are added from the app, and the file stays hand-editable — both keep
working.

```
╭ luvienne ────────────────────────────────────────────────────────────────────────────────────────────╮
│  press / to filter, ? for help                                                                       │
╰───────────────────╭ add host ────────────────────────────────────────────────────╮───────────────────╯
╭ categories ───────│        name  db-primary                                      │───────────────────╮
│  all hosts        │     address  10.20.1.5                                       │                   │
│  build 1          │        port  22                                              │b                  │
│  db 3             │        user  postgres                                        │b                  │
│  lab 1            │  categories  prod, db                                        │                   │
│  legacy 1         │        auth  key  ←/→ or space to change                     │                   │
│  obs 2            │    key path  ~/.ssh/id_ed25519                               │                   │
│  prod 7           │    remember  yes  keep the passphrase in the macOS Keychain  │ web               │
│  staging 2        │         via  bastion-eu                                      │ db                │
│  web 3            │     forward  L 15432:127.0.0.1:5432▌                         │                   │
│                   │                                                              │                   │
│                   │  ↵ save    tab next field    esc cancel                      │s                  │
│                   │                                                              │s                  │
│                   ╰──────────────────────────────────────────────────────────────╯                   │
│                    ││                                                                                │
╰────────────────────╯╰────────────────────────────────────────────────────────────────────────────────╯
 ? help   q quit   k/↑ move up   j/↓ move down   ↵ connect   / filter   t cycle tag   esc cancel / clear
```

Both are real frames rendered by the app, with invented hosts.

## What it does

- **Categories are tags, not a tree.** A host can be in `prod` and `db` at once.
- **Fuzzy filter** over name, address, user, tags and auth method — `/` then type.
- **Sessions outlive an attach.** `Ctrl-]` detaches and leaves the remote shell
  running; resume it later, including into full-screen programs like `vim` or
  `mc`. Idle connections are probed so a session that has quietly died is never
  offered for resume, and one that dies while detached says so rather than
  disappearing. `s` lists what is detached once you have more than a couple to
  keep track of, and `n` opens another shell on a host that already has one.
  Moving between sessions draws a rule naming the one you have arrived at and
  puts its recent output back, since they share the terminal's scrollback. `x`
  disconnects one outright, including a session too wedged to close politely.
- **Quick connect** with `c` for somewhere that is not in the list — type
  `user@host:port` the way you would after `ssh`. It uses the agent, asks for a
  username if you leave one out, and is not written to the inventory. Type a name
  you *have* saved and it connects with that entry's settings instead, jump host
  and all; add a user or a port (`root@web-01`) to reach the literal address.
- **Four ways to authenticate**: SSH agent, private key files (OpenSSH, PEM and
  PuTTY `.ppk` v2/v3), passwords, and keyboard-interactive — including servers
  that demand more than one of them. When the agent holds nothing a server will
  accept, it asks instead of giving up, the way `ssh` does.
- **Jump hosts** are a real tunnel, not a second login. The bastion moves bytes
  it cannot read and never sees the target's credentials.
- **Port forwarding**, `-L` and `-R`, attached to the host so you configure it
  once. Forwards keep working while the session is detached.
- **Import** from `~/.putty/sessions` and `~/.ssh/config`, with a confirmation
  that says what will need fixing afterwards rather than finding out one failed
  connection at a time.
- **Bulk edit** everything the filter is showing, for when sixty imported hosts
  all need the same correction.
- Optional **passphrase caching** in the macOS Keychain, off unless you turn it
  on per host.

## Requirements

- macOS or Linux. Passphrase caching is macOS-only — it uses the Keychain, and
  the option is simply absent elsewhere; everything else works on both.
- A terminal emulator — Terminal.app, iTerm2, Ghostty and WezTerm all work.
  This is a TUI, not a native GUI app.
- A stable Rust toolchain, if you are building from source rather than
  installing a package.

## Install

```sh
brew install clintcan/tap/luvienne
```

To track `main` instead of the latest release, `brew install --HEAD
clintcan/tap/luvienne`.

Or take a prebuilt binary from the
[releases page](https://github.com/clintcan/luvienne/releases/latest) — macOS
and Linux, on both arm64 and x86_64:

```sh
# Download the archive for your platform alongside SHA256SUMS, then check it
# before unpacking. --ignore-missing skips the archives you did not download.
shasum -a 256 -c SHA256SUMS --ignore-missing
tar xzf luvienne-v*-aarch64-apple-darwin.tar.gz
install -m 755 luvienne-v*-aarch64-apple-darwin/luvienne /usr/local/bin/
```

Fetched this way the binary just runs. Downloaded through a browser it does not:
macOS quarantines the archive and Gatekeeper blocks it, because these are ad-hoc
signed rather than notarized. `xattr -d com.apple.quarantine ./luvienne` clears
the flag.

From source:

```sh
git clone https://github.com/clintcan/luvienne.git
cd luvienne
cargo install --path .
```

Or `cargo run` in the clone to try it without installing.

## Getting started

Run `luvienne` to open on the host list, or name a host to connect straight to
it:

```sh
luvienne db-primary
```

That is the same as selecting it in the list, so the jump chain, forwards and
authentication all behave identically; detaching with `Ctrl-]` drops you into
the list rather than back to your shell. A name that is not in the inventory is
reported on stderr before the terminal is taken over.

On first run there are no hosts and the app says so. Press `a` to add one, or
write the file by hand — `~/.config/luvienne/hosts.toml`:

```toml
[[host]]
name = "bastion-eu"
address = "bastion.eu.example.net"
user = "jump"
tags = ["prod"]

[[host]]
name = "db-primary"
address = "10.20.1.5"
user = "postgres"
tags = ["prod", "db"]
auth = { method = "key", path = "~/.ssh/id_ed25519" }
# Reached by tunnelling through the bastion, which is the only machine that can
# see it. `jump` names another host in this file.
jump = "bastion-eu"
# psql -h 127.0.0.1 -p 15432 now reaches the database's own loopback.
forwards = [
  { direction = "local", listen_port = 15432, to_host = "127.0.0.1", to_port = 5432 },
]
```

No `auth` line means the SSH agent, which is the best option when you have one.
See [`hosts.example.toml`](hosts.example.toml) for every field, commented.

## Keys

| key | |
| --- | --- |
| `↵` | connect, or resume a detached session |
| `Ctrl-]` | detach, leaving the remote shell running |
| `c` | quick connect to `user@host[:port]`, without saving it |
| `n` | open another session to the selected host |
| `s` | list detached sessions; `↵` resumes one, `esc` goes back |
| `x` | disconnect a session, after confirming — works when it has stopped responding |
| `/` | filter; `esc` clears it |
| `t` | cycle the category filter |
| `j` `k` or `↓` `↑` | move |
| `a` `e` `d` | add, edit, delete a host |
| `b` | bulk-edit every host currently shown |
| `i` | import from PuTTY and `~/.ssh/config` |
| `?` | help |
| `q` | quit, closing every session |

In the host form, `tab` moves between fields and `^O` on the key path opens a
file browser. Text fields edit in place — `←`/`→` move the caret, `home`/`end`
jump to either end, and `delete` removes forwards. On the auth and remember
selectors, `←`/`→` or space change the choice instead.

`esc` cancels a connection that is in progress — which takes priority over
clearing the filter, since a connect going nowhere is the more urgent thing to
stop and a filter is cheap to retype.

## Security

The parts worth knowing before you trust it with production hosts:

- **Host key verification is on**, checked against `~/.ssh/known_hosts`. An
  unknown host prompts and is only remembered on an explicit `y`. A *changed*
  key is a hard error with no way through from the UI, and there is no global
  "disable host key checking" switch.
- **No secrets in the config file.** `hosts.toml` holds a reference to a key —
  a path, or a Keychain item — and never key material or a password.
- **Passphrase caching is opt-in per host** and deletes what it stored when you
  turn it off. There is no global switch, which would opt in every host at once
  including the ones whose keys you mean to type.
- **Port forwards bind loopback** unless you write an address out in full, and
  only ports you asked to forward are accepted from the server.
- Decrypted keys and passphrases are zeroized, and nothing secret reaches a log
  or an error message.
- It speaks SSH itself rather than shelling out to `/usr/bin/ssh`, so no
  arguments leak into the process table.

## Status

Working and used daily against real servers, but young, and a personal project
rather than a supported product. Not on crates.io.

Known gaps: no SOCKS (`ssh -D`), no file transfer, no agent forwarding.
Two-factor auth is exercised against a real server that accepts a key and then
demands a second factor (`AuthenticationMethods publickey,keyboard-interactive`);
see [`TESTING.md`](TESTING.md). Several prompts inside a *single*
keyboard-interactive round — a TOTP module asking for a password and a code
together — is implemented but still untested. Developed on macOS and verified on Linux (arm64
Ubuntu) as far as building, the whole test suite, and a real session including
detach and resume. tmux is still unknown territory.

[`TESTING.md`](TESTING.md) covers running it against a throwaway server;
[`DESIGN.md`](DESIGN.md) is the design rationale, including why several obvious
approaches were the wrong ones.

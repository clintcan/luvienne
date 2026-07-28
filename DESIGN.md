# Design notes

Why luvienne is built the way it is, aimed at anyone changing it. See
[`README.md`](README.md) for what it does and how to run it.

Most of what follows records a decision that has a plausible-looking
alternative, and several record a bug that was shipped before the rule was
understood. Treat the reasoning as the point; the code is only its current
expression.

## Interface model

This is a **TUI**, not a native macOS GUI. It runs inside a terminal emulator
(Terminal.app, iTerm2, Ghostty, WezTerm) and draws with ratatui + crossterm. When
docs or commit messages say "UI", they mean the ratatui view layer.

The visual target is "modern and slick" in the TUI sense:

- Rounded borders, generous padding, no dense ASCII art.
- A restrained palette that adapts to the terminal's light/dark background; never
  hardcode raw ANSI colors in widget code — go through the theme module.
- Truecolor when the terminal advertises it, graceful 256-color fallback.
- Every action reachable by keyboard; the mouse is a convenience, never a requirement.
- Fuzzy filter over hosts as the primary navigation tool.
- **The window title is ours to set.** A terminal program inherits whatever title
  the shell left, which is why this showed up as "Terminal". `main` saves the old
  title (XTWINOPS `CSI 22;0t`), sets `luvienne`, and restores it on exit and in
  the panic hook. While a session owns the terminal the title is the host name —
  that is what you scan tabs for. Terminals without XTWINOPS ignore save/restore,
  and the only cost is our title outliving the process.

## Architecture

```
src/
  main.rs           entry point, runtime + terminal setup
  app/              application state, event loop, key dispatch (BINDINGS table)
    form.rs         add/edit host form: fields, validation, Host conversion
    picker.rs       file browser for choosing a key file
  ui/               ratatui rendering — pure functions of &App, no I/O
    theme.rs        colors, borders, symbols; single source of truth for styling
  ssh/              russh session lifecycle, channels, PTY
  auth/             private key loading (OpenSSH, PEM, PuTTY .ppk)
  config/           host inventory, categories, persistence
  keystore/         macOS Keychain integration for cached passphrases
```

Two hard boundaries worth preserving:

1. **`ui/` never performs I/O.** Rendering is a pure function of application state.
   Anything that touches the network, filesystem, or Keychain lives elsewhere and
   communicates results back into state.
2. **The loop redraws only when something changed.** `run` keeps a `dirty` flag;
   painting every pass cost 2–4% of a core around the clock for a UI that is
   usually idle. Anything that changes what is on screen **must** set it —
   `drain_background` and `prune_dead_sessions` return whether they changed
   anything for exactly this reason, and `Event::Resize` marks dirty itself
   because nothing else will notice a new terminal size. Add state without
   marking it dirty and the UI silently stops updating.
3. **The event loop never blocks.** SSH work runs on tokio tasks and reports progress
   through a channel; the render loop stays responsive during connects, DNS lookups,
   and key decryption.

## Session model

Being a TUI is what makes this tractable: we do not implement a terminal emulator.
Once a session is authenticated, the app suspends its own rendering, leaves raw mode
in place, and pipes the russh channel directly to stdin/stdout — the user's existing
terminal emulator does the VT100 work, scrollback, and font rendering. On disconnect
we restore the alternate screen and return to the host list.

**A session outlives any one attach.** `Ctrl-]` detaches back to the host list
leaving the remote shell running; the list marks it `●` and `↵` resumes it.

`ssh/session.rs` owns the channel in its own task and always drains it. If the
foreground simply stopped reading while detached, the channel queue would fill,
the russh session task would block inside that send, and the whole connection —
keepalives included — would stall until the server dropped it. Attaching tells
that task where to send output; detaching tells it to buffer into a capped
backlog (`BACKLOG_LIMIT`), so a detached `tail -f` loses its middle, not its end.

- The PTY and shell are requested **once, in `connect`** — never in `attach`, or
  every resume would start another shell on the remote.
- The russh `Handle` is moved into the session task, so the connection is torn
  down exactly when the session ends. Leaking it to keep it alive would strand a
  TCP connection and its task for the life of the process.
- A detached session can die on its own; `App::session_for` filters on
  `has_ended` and `prune_dead_sessions` runs each pass, so `●` never lies.
- Quitting closes every session rather than stranding shells on the server.
- **`CONNECT_TIMEOUT` bounds the dial only, never the handshake.** `check_server_key`
  runs *inside* the SSH handshake and blocks on the user answering the host key
  prompt, so a timeout around the handshake is a stopwatch on someone reading a
  fingerprint — an early version did exactly that and failed a connect after a
  deliberate pause. The dial (TCP, or the forward through the previous hop) is
  bounded; everything after it is escapable with `esc` instead.
- **`esc` cancels a connect in flight**, aborting the task. It keeps its old job of
  clearing the filter when nothing is connecting — a connect going nowhere is the
  more urgent thing to stop, and a filter is cheap to retype.
- **Idle connections are probed** (`KEEPALIVE_INTERVAL`, `KEEPALIVE_MAX`), the
  equivalent of OpenSSH's `ServerAliveInterval`/`CountMax`. russh sends nothing on
  an idle link by default, and NAT and stateful firewalls drop idle flows silently
  — so a detached session, which is idle by design, would sit in the list looking
  alive and resume into a shell that is never coming back. Verified by freezing the
  server: an unguarded build resumed into the dead session, a guarded one pruned it.
  `inactivity_timeout` stays unset on purpose — it garbage-collects *quiet*
  connections, which is exactly what a parked session is.

**Resuming into a full-screen program** (mc, vim, htop) needs two things that are
easy to get wrong, and both were:

- **The terminal must be back in the buffer the remote thinks it is using.**
  Detaching leaves us in the primary screen; a program that had switched to the
  alternate one would otherwise paint over the user's scrollback. `AltScreenTracker`
  watches session output for smcup/rmcup (`?1049`, `?1047`, `?47`) and `attach`
  restores that mode before handing the terminal back. This is the **only** place
  session bytes are inspected — a state flag, not a terminal emulator. Keep it that
  way; interpreting content is how this turns into writing one.
- **A resize must actually change the size to force a repaint.** The kernel raises
  `SIGWINCH` only when the dimensions differ, so re-sending the current size is
  silently ignored and the program never redraws — a resumed `mc` came back to a
  stale screen for exactly this reason. `attach` nudges by one row and then sets
  the real size.
- The detach hint prints on first attach only. On a resume the remote may be
  mid-screen, and our own line would corrupt the display we just restored.

**Connecting is background work; attaching is foreground work.** This split is the
central rule of the codebase:

- `ssh::connect` runs on the tokio runtime. It resolves, verifies the host key,
  authenticates, and opens a channel, reporting progress as `SshEvent`s. It never
  touches the terminal.
- `ssh::attach` runs on the *main thread*, called from the event loop via
  `Handle::block_on`, because it takes the terminal over completely. The loop hands
  it off through `App::pending_session` and is paused for the session's duration.

A background task that needs to ask the user something sends a `oneshot::Sender`
through the event channel and awaits the reply — that's how host key confirmation
crosses the thread boundary without the SSH task touching UI state.

Consequences to respect:

- `ui::suspend` leaves the alternate screen but **keeps raw mode on** — the remote
  shell needs unbuffered, unechoed keystrokes. Disabling it breaks interactive
  programs on the far end.
- **`ui::suspend` also shows the cursor, and `ui::resume` hides it again.** ratatui
  hides the cursor on every draw (this app paints its own `▌` in text fields), and
  the remote shell never asks for it back — without the `Show`, you type into a
  session with no visible cursor.
- **`ratatui::restore` does not show the cursor either.** `main` calls
  `ui::show_cursor` after `ratatui::run`, and chains a panic hook that does the
  same, or quitting leaves the user's shell with an invisible cursor until they
  run `reset`. ratatui's hook restores the terminal first and then calls ours, so
  the ordering is already correct.
- `ui::resume` runs unconditionally, before the session result is inspected. An SSH
  error must never strand the user in a half-suspended terminal.
- **Do not call `Terminal::clear` on the resume path.** It issues a DSR cursor-position
  query (`ESC[6n`) and blocks on a reply. Real terminals answer; some multiplexer
  setups and every headless harness do not, and a timeout there discards a session
  that already succeeded. The alternate screen is blank on re-entry anyway, so
  `Terminal::resize` is used instead — same buffer reset, no round-trip.
- Window resize forwards `SIGWINCH` to the remote as a `window-change` request while
  a session is attached. Size comes from `TIOCGWINSZ`, including pixel dimensions —
  remote programs that draw images (sixel, kitty graphics) need those, and reporting
  zeroes tells them nothing.
- **Session stdin must stay readiness-based** (`RawReader` over `AsyncFd`), never
  `tokio::io::stdin`. A blocking read cannot be cancelled: when `select!` drops the
  read future at end of session, the blocking thread is still inside `read(2)` and
  swallows the user's next keystroke — which by then belongs to the host list.
  `ssh::tests::a_cancelled_read_consumes_nothing` is the regression guard; it hangs
  rather than passes if someone reintroduces a blocking reader.
- **`RawReader::open` opens the terminal by name (`ttyname`), never by setting
  `O_NONBLOCK` on fd 0.** `O_NONBLOCK` is a property of the open file description,
  and stdin/stdout/stderr on a terminal share one — so flipping it "on stdin" makes
  **stdout** non-blocking too. The first burst of session output big enough to fill
  the terminal buffer (a plain `ls`, around 1 KiB) then failed the write with
  `EAGAIN`, ending the session and dropping the user back to the host list. Opening
  `/dev/ttysNNN` separately gives us our own description and leaves stdout alone.
  `ssh::tests::borrowing_a_descriptor_makes_its_siblings_nonblocking_too` pins the
  underlying OS behaviour so the reasoning survives.
- The stdin fallback (no terminal name available) still flips the flag, so
  `write_session_output` retries on `WouldBlock` rather than treating it as a dead
  session. The `NonBlocking` guard restores the original flags on drop.
- Do not try to intercept or filter session bytes for UI purposes. Anything that
  parses the remote's output is the first step toward writing a terminal emulator,
  which is explicitly out of scope.

## Host inventory and categories

Hosts are the core domain object. Each has a name, address, port, user, an auth
strategy, optional jump host, and a set of tags used for categorization.

- Categories are **tags**, not a rigid tree. A host can be in `prod` and `db` at once.
  The sidebar renders tags as a browsable list; selecting one filters the host table.
- The inventory is stored as TOML under `~/.config/luvienne/hosts.toml`. See
  `hosts.example.toml` for the schema. A missing file is a first run, not an error;
  malformed TOML *is* an error.
- **`b` bulk-edits every host currently shown.** The filter *is* the selection —
  narrow with `/` or `t`, then edit what is left — rather than inventing a second
  way to pick hosts alongside one that already works. `Host::matches` includes the
  auth method so `/key` selects every key-auth host, which is what makes the bulk
  edit able to target them.
- A bulk edit applies **only the fields actually touched**, tracked explicitly
  rather than inferred from emptiness. Inferring would make it impossible to
  *clear* a field across many hosts — which is exactly how you set sixty imported
  hosts back to "ask for the username". Name and address are absent from the bulk
  form: they identify a host, and setting sixty to one name is never meant.
- Hosts are managed **from the UI** — `a` add, `e` edit, `d` delete — and the file
  stays hand-editable. Both have to keep working.
- **Key paths are not restricted to `~/.ssh`.** Any absolute path works and always
  did; `^O` on the key path field opens a file browser (`app/picker.rs`) so a key
  outside the usual place doesn't have to be typed blind. The browser shows dotfiles
  by default — hiding them would make `~/.ssh` itself unreachable — and every
  listing except the filesystem root leads with a `..` row. Navigating up worked
  from the first version via `←`/backspace, but with no `..` in the list the
  browser read as though it had trapped you in whichever directory it opened in.
- The browser is a **TUI list, not the macOS native dialog**. A GUI panel would break
  the terminal model and would be useless when this runs over SSH on a remote host,
  where the keys being chosen live on the remote filesystem.
- **Saving edits the document, it does not re-serialize it.** `Inventory::save_to`
  uses `toml_edit` to update the existing `[[host]]` tables in place. A plain
  `toml::to_string` would delete every comment in the file and rewrite
  `auth = { ... }` as a `[host.auth]` sub-table — reformatting a file the user
  wrote, the first time they add a host from the UI.
- **Tables are matched to hosts by name and moved wholesale**, and each is given
  a fresh `set_position` as the array is rebuilt. Three separate bugs live here:
  overwriting by index relabels every host below a deletion; a positional
  fallback (there so a renamed host keeps its note) hands a *newly inserted*
  host the next one's note unless it is limited to the unchanged-length case;
  and a cloned `toml_edit` table remembers its old document position, so
  reordering renders in the old order unless the position is reset.
- **Defaults are only written when the key already exists.** Otherwise adding one
  host sprinkles `port = 22` and `tags = []` through every other entry, editing
  lines the user never touched.
- Writes are atomic — temp file in the same directory, then rename — and a failed
  write rolls the in-memory change back, so what is on screen is what is on disk.
- **Jump hosts are a tunnel, not a second login.** `jump = "bastion"` makes
  `connect` dial the bastion, open a `direct-tcpip` forward to the target, and run
  its own SSH handshake over that stream. The bastion moves bytes it cannot read,
  verifies nothing, and never sees the target's credentials — unlike SSH-ing in and
  typing `ssh target`, where it terminates the session and would need your key.
  Every hop's host key is checked against `known_hosts` and every hop authenticates
  with its own `AuthRef`.
- `Inventory::connection_chain` resolves the chain and is where cycles are caught.
  `a` jumping via `b` and `b` via `a` is easy to write by hand and would otherwise
  recurse until the stack ran out; `MAX_JUMPS` bounds the depth as well.
- **Every hop's `Handle` must outlive the session.** The tunnel to hop N runs inside
  hop N-1's connection, so they are all moved into the session task; dropping an
  earlier one collapses everything nested in it.
- A bastion with `AllowTcpForwarding no` is the common failure. russh reports it as
  "AdministrativelyProhibited", which says nothing actionable, so it is mapped to
  `ForwardRefused` naming the jump host and the setting.
## Port forwarding

`ssh -L` and `ssh -R`, attached to the host rather than to a connect-time flag —
a tunnel you need once you will need every time, and not re-typing connection
details is the point of the app. Verified end to end against a real server in
both directions, each with a control proving the target is unreachable without
the tunnel. `ssh -D` (SOCKS) is **not** implemented; `ssh_config`'s
`DynamicForward` is counted and reported by the importer rather than dropped.

- **Local forwards bind loopback unless told otherwise.** `0.0.0.0` publishes
  whatever is at the far end — a production database, an admin panel — to
  anyone who can reach this machine. `ssh` defaults the same way; here you have
  to write the address out in full, which is at least hard to do by accident.
  There is a test that binds for real and asks the OS what it got, rather than
  inspecting the string we passed in.
- **Only ports we asked to forward are accepted** (`forward_for_port`). russh's
  default handler accepts *every* channel a server offers, which would let a
  machine we are merely logged into open connections to arbitrary addresses on
  this side, through the firewall, as us. A local forward's port must never
  match either: those are sockets we opened here, so a server-opened channel
  naming one is unrequested by definition.
- **Forwards are stored field-by-field, not as a spec string**, so `u16` rejects
  a bad port when the file is read rather than at connect time. The terse
  `L 8080:db:5432` form is the *form field's* representation only, and the
  `ssh_config` importer normalises its space-separated spelling into that same
  form rather than growing a second parser that could disagree about ports or
  IPv6 brackets.
- **The listeners are aborted when the session task ends** (`AbortOnDrop`).
  Each holds an `Arc` on the connection's handle, so one left running would keep
  the transport — and the port — alive after the session that owned it had gone,
  defeating the reason the handles are moved into the session in the first place.
- **A forward that failed to come up outranks the session outcome** in the status
  line. It is reported once as a progress line during the connect and then buried
  under "attaching…" seconds later; without `session_status` preferring it, the
  only durable record would be gone by the time anyone could read it. Believing
  in a tunnel you do not have means using the port and reaching whatever else was
  listening on it — which is worse than knowing it failed. Failures are collected
  rather than fatal, matching `ssh`.
- One failed connection must never take a listener down with it, or a target
  that refuses once disables the tunnel for the rest of the session.

- **`~/.ssh/config` import** is read-only and always must be: that file belongs to
  `ssh`, and a connection manager that rewrites it is overstepping.
- The ssh config format is not key-value. `Host` opens a block, options are
  inherited, and the *first* value obtained wins — so a block's own setting beats
  an inherited one, not the other way round. The reading is deliberately
  conservative: wildcard patterns (`Host *`, `prod-*`) are matchers rather than
  names and are skipped, `Match` blocks are conditional on state we cannot
  evaluate, `Include` is counted rather than followed, extra aliases name the same
  host rather than new ones, and a `ProxyJump` that is multi-hop or points outside
  the config is dropped — keeping it would fail chain resolution on every connect.
  Every one of those is reported in the confirmation rather than silently applied.
- Two distinctions the parser has to keep straight, both of which it got wrong
  first: options inside `Host *` are global, but options inside a *narrower*
  pattern (`Host prod-*`) apply only to hosts we cannot identify and must be
  dropped rather than inherited by everything; and repeated aliases are one host
  whose options merge (first value wins), not two hosts of the same name — which
  would make resuming and jump resolution ambiguous.
- Both importers report through `import::Imported`, so the confirmation modal knows
  nothing about PuTTY session files or ssh config syntax. A third source is a new
  scanner, not a new branch in the UI.
- **PuTTY import** (`i`) reads `~/.putty/sessions`, one `Key=Value` file per session
  with `%XX`-escaped filenames. It is scan-then-confirm: adding dozens of hosts to
  someone's config is not a single-keystroke action, and the modal states what will
  need fixing afterwards. Imports are tagged `putty` and skip names already present,
  so re-importing is safe.
- The import **never invents or silently drops information**. Sessions migrated from
  Windows PuTTY carry key paths like `D:\keys\x.ppk` that cannot resolve here; those
  are imported as-is, because knowing which key a host wanted is the useful part and
  `^O` makes repointing it easy. PuTTY has no username on most sessions (it prompts
  at connect), so the local one is assumed — the same default `ssh` uses, never root.
  PuTTY's proxy settings are SOCKS/HTTP/local-command, not an SSH jump host, so
  nothing maps to `jump`.
- **Secrets never go in `hosts.toml`.** It stores a reference to a key (path or
  Keychain item), never key material or a password.

## Authentication

All three methods are wired up and verified against a real sshd.

1. **SSH agent** — via `SSH_AUTH_SOCK`. Preferred when available; the user's key
   never leaves the agent. Every offered identity is tried in order until one is
   accepted; certificate identities are skipped (they need a different method).
2. **Private key files** — OpenSSH format (`ed25519`, `ecdsa`, `rsa`) and legacy PEM.
   An unencrypted key never prompts: `load_key_interactive` always tries with no
   passphrase first, and only prompts if that returns `PassphraseRequired`. Up to
   three attempts, matching `ssh(1)`.
   - Decryption runs on `spawn_blocking`. It is CPU-bound and slow enough to stall a
     runtime worker — the fixture tests alone take ~3s, almost all Argon2.
   - RSA needs an explicit hash algorithm. `PrivateKeyWithHashAlg::new(key, None)`
     means SHA-1 `ssh-rsa`, which OpenSSH 8.8+ rejects by default, so
     `authenticate_with_key` tries SHA-512, then SHA-256, then legacy SHA-1. russh
     ignores the parameter for non-RSA keys, so other types make one attempt.
   - Paths go through `auth::expand_tilde`. `~/.ssh/id_ed25519` is what people
     actually write in `hosts.toml`, and an unexpanded `~` is a directory that
     doesn't exist.
3. **PuTTY `.ppk`** — versions 2 and 3. `russh::keys::decode_secret_key` sniffs the
   format by content and handles PPK natively, Argon2 included, so there is no
   separate PPK code path and **no hand-rolled parser** — don't add one. v3's Argon2
   derivation is deliberately slow, so decryption must run off the render thread with
   a progress indicator. Never write a converted key back to disk.
**A server may demand more than one method.** `AuthenticationMethods
publickey,keyboard-interactive` is standard on hardened servers: it accepts the
first method and replies with a *partial success* — "that counted, now do
another one". Each method therefore returns `Step::Done` or `Step::More(methods)`
and `authenticate` chains them, preferring an interactive method for the second
factor since re-offering the key would only loop. Treating partial success as
failure reported "the server rejected the key" about a key the server had just
accepted; verified against a real Ubuntu OpenSSH 9.6 host configured this way.

4. **Password / keyboard-interactive** — last resort, entered in a masked field.
   `AuthRef::Password` covers both, because "password auth" means different things
   to different servers: stock OpenSSH accepts the `password` method, while a
   PAM-backed one commonly offers only `keyboard-interactive`.
   - **Probe before prompting.** `authenticate_with_password` sends a `none` auth
     request first to learn which methods the server accepts, exactly as `ssh(1)`
     does. Without it, a keyboard-interactive-only server makes the user type
     their password, rejects it, then asks again through the other method — the
     same secret typed twice for one login.
   - Keyboard-interactive prompt text comes from the server and is rendered
     verbatim; that is how 2FA and PAM messages reach the user. Each prompt's
     `echo` flag decides whether input is masked — not every challenge is secret.
   - `MAX_KEYBOARD_ROUNDS` bounds the `InfoRequest` loop. A misbehaving or hostile
     server could otherwise keep prompting forever with no way out.
   - Unavoidable leak, documented at the call site: `authenticate_password` takes
     `Into<String>`, so russh holds a copy we cannot zeroize. Ours is still wiped.

**Passphrase caching** (`keystore/`) keeps a key's passphrase in the macOS
Keychain so an encrypted key is typed once rather than every connect. It is
**off unless the host says `cache_passphrase = true`**, and that flag governs
reading as much as writing: a host that has not opted in prompts even when the
very key it uses is already cached. There is deliberately no global switch —
one would opt in every host at once, including the ones whose keys the user
means to type.

- **Entries are keyed by key file, not by host.** A passphrase belongs to the
  key, not to the machine you are logging into; twenty hosts sharing one `.ppk`
  share one entry. Keyed by host, `forget` on one would report the secret gone
  while nineteen copies stayed behind. The account string is
  `key:<path with ~ expanded>`, namespaced so a later cache of something else
  cannot collide with it.
- **What is reported forgotten is what was actually removed.** `forget` returns
  whether an entry was there, and the status counts only real removals. A host
  can carry the flag having never stored anything — never connected to, or on a
  platform with no keychain at all — and counting *attempts* announced "forgot 1
  cached passphrase" about a secret that never existed. Claiming a secret was
  deleted when it was not is the wrong direction to be wrong in.
- **The toggle is absent where there is no keychain** (`keystore::is_supported`),
  rather than offered and always failing. A config that sets the flag anyway is
  left alone rather than quietly cleared — the same file is likely synced to a
  Mac, where it works. The tests for that field are `cfg`-gated to macOS for the
  same reason; `cargo test` is expected to pass on Linux too.
- **Turning it off deletes what was stored.** `App::persist` diffs the set of
  cached key ids across every save and forgets what the inventory no longer
  refers to — which covers opting out, switching to agent auth, repointing the
  key path, deleting the host, and a bulk edit doing any of those to sixty hosts
  at once. `orphaned_key_ids` is the pure part and is where the rule is tested.
  An opt-out that only stopped *reading* would leave the passphrase in the
  Keychain while the form said caching was off.
- The `kept` set in that diff is load-bearing: without it, renaming a host
  throws away its passphrase, and one host of twenty opting out silently breaks
  the other nineteen. There are tests for both.
- **A stale entry is dropped, not re-offered.** If the cached passphrase no
  longer decrypts the key — the passphrase changed, or the file at that path was
  replaced — it is forgotten and the user is asked, rather than failing the same
  way on every connect. The same applies when the key at that path stops needing
  a passphrase at all: nothing would ever read the stored one again, and no
  later edit could clean it up, because the host still names that path with
  caching on.
- **The bulk form always offers the toggle; a single-host form only offers it
  for key auth.** A bulk edit does not know its targets' methods, and hiding it
  behind `auth = key` there would mean the only way to reach it is to cycle the
  method — stamping one key path across every selected host and destroying the
  paths that are the whole reason for turning caching on. `apply_to` therefore
  gates the flag on the **host's** auth, not the form's; gating on the form
  silently refuses every edit the field exists for.
- Every Keychain call goes through `spawn_blocking`. macOS may put up an access
  dialog, and that blocks for as long as the user takes to answer it.
- Reading and storing are both reported in the status line. Opting in is
  consent, but a secret being written is still not something to do quietly.

## Security rules

These are not stylistic preferences. Treat a violation as a bug:

- Never log, print, or include in an error message: private keys, passphrases,
  passwords, or agent responses. Redact at the point of construction.
- Zeroize decrypted key material and passphrases when dropped (`zeroize` crate).
  The passphrase is `Zeroizing<String>` end to end — the UI input buffer, the
  channel that carries it, and the decrypt call. It is wiped on submit, on cancel,
  and on drop.
- **The secret modal renders bullets, never characters** — unless the request
  explicitly sets `echo`, which only a keyboard-interactive server can ask for.
  One modal (`render_secret_prompt`) serves passphrases, passwords, and challenges,
  so a masking regression in one is a regression in all three; there are tests
  asserting against the rendered cells for each.
- While typing a secret, the binding table does **not** apply — every printable key
  is content. `q` must not quit, `/` must not open the filter.
- `SshError::AuthFailed` carries the `method` that failed. It used to hardcode
  "no agent identity was accepted", which meant a *password* host reported an agent
  problem and sent you hunting the wrong thing.
- Host key verification is **on** by default, checked against `~/.ssh/known_hosts` in
  `ssh::Client::check_server_key`. Three outcomes, and keeping them distinct is the
  whole point:
  - **match** → accept silently
  - **changed** (`Error::KeyChanged`) → hard error naming the `known_hosts` line. No
    prompt, no override, no way through from the UI.
  - **unknown** → prompt, and call `learn_known_hosts` only on an explicit `y`
- The host key prompt **fails closed on every path**. `y` accepts; `n`, `esc`, a
  dropped channel, and quitting mid-prompt all refuse. No other key answers it —
  notably Enter, so an unknown host can't be accepted by reflex. There are tests for
  each of these; if you touch the prompt, keep them passing.
- No "disable host key checking" global toggle. If an escape hatch is ever needed it
  is per-host, explicit, and visibly marked in the UI.
- Do not shell out to `/usr/bin/ssh`. This client speaks SSH itself; shelling out
  would leak arguments into the process table.

## Stack

Rust 2024 edition.

| Concern            | Crate                                 |
| ------------------ | ------------------------------------- |
| TUI rendering      | `ratatui`                             |
| SSH protocol       | `russh` (keys via `russh::keys`)      |
| Async runtime      | `tokio`                               |
| Errors             | `thiserror` (modules), `color-eyre` (main) |
| Config             | `serde` + `toml`, paths via `directories` |
| Secret hygiene     | `zeroize`                             |
| Keychain           | `security-framework` (macOS only)     |

Two dependency notes that are easy to get wrong:

- **crossterm is not a direct dependency.** Use `ratatui::crossterm`, which is
  re-exported at the version ratatui was built against. Adding a direct `crossterm`
  entry invites a version skew that fails in confusing ways at runtime.
- **`russh-keys` is obsolete.** It was folded into `russh` as `russh::keys`; the
  standalone crate on crates.io lags several versions behind. Don't re-add it.

## Commands

```bash
cargo run                  # launch the client
cargo test                 # unit + integration tests
cargo clippy -- -D warnings
cargo fmt
```

TUI apps and test harnesses fight over the terminal. Test rendering by asserting
against ratatui's `TestBackend` buffer rather than by spawning a real terminal, and
test SSH logic against a local server fixture rather than a real remote host.

See `TESTING.md` for running against a real server (throwaway Docker sshd) and for
`scripts/drive_tui.py`, which drives the binary on a real pty with timed keystrokes.
Note that `script -q /dev/null ./binary` does *not* work as a harness — input never
reaches the app and the pty reports no window size.

`tests/fixtures/` holds throwaway keys produced by real `puttygen` and `ssh-keygen`
— PPK v2, PPK v3 plain, PPK v3 Argon2-encrypted, and an encrypted OpenSSH key,
passphrase `hunter2`. Prefer extending these over hand-writing key files: PPK v3's
MAC and KDF parameters are not something to approximate by hand. See that
directory's README to regenerate.

## Conventions

- Stable toolchain. `cargo clippy --all-targets -- -D warnings` must pass clean
  **on Linux as well as macOS** — see `TESTING.md` for the container that checks
  it. The keystore is where this breaks: every `KeystoreError` variant is dead
  on the platform that cannot produce it, so each carries a `cfg_attr` `allow`
  for the *other* side rather than `cfg`-ing the variants away, which would push
  the split into every caller and every test that matches on them.
- Fallible functions return `Result`; `unwrap()`/`expect()` only in tests and in
  `main.rs` startup where failure should abort anyway.
- Render functions take `(&App, &Theme, &mut Frame, Rect)` — plain functions, not
  stateful structs, unless ratatui's `StatefulWidget` is genuinely needed.
- **Scrolling viewports must subtract every row of chrome.** The host list has
  three — two borders *and* the table's column header — and counting only the
  borders rendered one row more than fit, silently clipping the selected row off
  the bottom. Tests assert the selected item is actually on screen; when writing
  one, scope the assertion to the widget, since a name can appear in a
  neighbouring panel and make the test pass with no scrolling at all.
- **A scrolling list draws a scrollbar on its right border**, via `scroll_track`
  and `render_scrollbar`. Three things there are easy to get wrong, and two were:
  - `scroll_track` takes the **viewport the caller already computed**, so the
    track cannot disagree with the list about how many rows there are, and a
    `chrome_above` count the caller states. That count differs per list — one
    for the sidebar, two for the host table's header, three for the picker's
    path line — and getting it wrong is silent: the bar still renders, just
    describing rows that are not where it says they are. Each has a test that
    anchors the thumb to a **row of real content**, never to a fixed line
    number, which moves in step with the bug and pins nothing.
  - `ScrollbarState::new` is given the scrollable **range** (`total - viewport`),
    not the item count. With the item count the thumb never reaches the bottom,
    so a fully scrolled list still looks like it has more below.
  - The track symbol is the **border glyph**, not ratatui's default `║`, which
    cuts a double-ruled stripe down a panel drawn in rounded single lines. Only
    the thumb should be visible.
  - Nothing is drawn when the list fits. A track that is always full says only
    "there is a list", which is already on screen.
- **The name column is sized to its content** (`name_column_width`), not fixed.
  It was 22 columns, which cut "Defenders Matrix Med Prod Workers" down to
  "Defenders Matrix Me" on a window with room to spare — every other column is
  a `Min` constraint, so they absorbed all the slack and the one column that
  needed it never grew. Sized from the **whole inventory**, not the hosts on
  screen: fitting it to the filtered list packs tighter, but the filter is the
  primary way around this app, and sizing to it slides every other column
  sideways on each keystroke of the commonest interaction there is. A stable
  table costs a few columns when a filter leaves only short names, and that is
  the cheaper of the two.
  - It is deliberately **not** capped against the window width. A hand-rolled
    cap reserving room for the other columns was written first and rendering
    proved it changed nothing — ratatui's solver already holds a `Min` column
    at its minimum against an oversized `Length`. All the cap added was a
    second copy of the other columns' minimums, waiting to drift. The test that
    a 300-character name cannot squeeze `destination` off the edge is still
    there, now pinning that assumption about ratatui rather than our own code.
- All arithmetic on `Rect` width/height is saturating. A 20×5 terminal must render
  without panicking; there's a test that checks exactly this.
- `App::selected` indexes the **visible** list, not `inventory.hosts`. With a filter
  active the two differ, so edit and delete must resolve through
  `selected_inventory_index()`. Using the visible index directly silently modifies
  the wrong host — there are tests pinning this for both operations.
- Control chords are commands, never text. Every text-entry arm guards on
  `!KeyModifiers::CONTROL`, or `^O` types a literal `o` into the field.
- New key bindings go in `app::BINDINGS` and nowhere else. Order matters there: the
  footer is truncated at the window width, so `? help` leads — it lists everything
  that got cut. Dispatch, the footer
  hints, and the help overlay all read that one table, so they cannot drift apart.
  Adding a `match` on a key code elsewhere breaks that guarantee.
- **`main` uses `try_init`, not `ratatui::run`.** With no terminal — piped output,
  cron, CI — `run` panics and reports a crash inside ratatui, which tells the user
  nothing. `try_init` turns that into a plain "needs a terminal" error.
- **Panic hook ordering:** `ratatui::init` installs its own terminal-restoring hook
  and it must sit *on top of* color-eyre's, so `color_eyre::install()` has to run
  first. Reversing them leaves the user in raw mode staring at a backtrace.
- **The form's label column is ten characters wide** and `{:>10}` does not
  truncate, so a longer label pushes its own row's value out of line with every
  other field's. Two tests pin it: one on the strings, one on the rendered
  columns.
- **A choice field renders its hint after the value**, not as a placeholder. The
  placeholder only fires for an empty field, and a choice field always has a
  value — so `Field::Auth`'s hint had never appeared on screen at all.
- **A form field shows the *end* of its value** (`visible_tail`), never the
  start. Fields only append and backspace, so the caret is always at the end,
  and that is the part that has to stay on screen. Rendering the value in full
  and letting the popup clip it meant typing past the edge was invisible: the
  characters landed in the buffer, the display stopped changing, and a key path
  with a typo looked exactly like one without. It also happens to be the right
  end — a path's filename identifies it better than its leading directories.
  - The row reserves the caret column whether or not it has focus, so tabbing
    between fields does not slide the text sideways by one.
  - **The symptom is a missing caret, not content past the border.** ratatui
    clips at the widget boundary, so overflow is never visible as a row running
    over its own border — the `▌` after the value is simply pushed off and
    dropped. A test looking for content past the border passed against the
    unfixed code; the one that catches it asserts the caret is still there.
  - The value shown is never a *different* string from the buffer. Compressing
    `/Users/you` to `~` would fit more on screen and would be lying about what
    backspace is about to remove.
  - **Every text input paints its own caret**, so every one of them has this
    bug until it is clipped: the form fields, the `/` filter, and the secret
    prompt — whose label is server-supplied and so of unknown width. Fixing only
    the form left the two used most often still going blind as you type.
  - **Placeholder hints need clipping too**, and keep their *start*
    (`visible_head`) since they are read rather than edited. An unclipped hint
    pushes the caret off the row, and an empty focused field is exactly where
    the caret matters most.
  - **Width is display columns, not characters** (`unicode-width`). A CJK
    character occupies two columns, so counting characters keeps twice as much
    text as fits and the row overflows again — the same bug one metric further
    down. `unicode-width` is a direct dependency for this; unlike crossterm it
    shares no types with ratatui, so there is nothing for a version to skew.

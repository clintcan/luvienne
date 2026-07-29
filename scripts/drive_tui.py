#!/usr/bin/env python3
"""Drive the luvienne TUI on a real pty and record what it draws.

Usage: drive_tui.py <binary> [script...] [-- <binary arg>...]
Script steps are "delay:keys" pairs, e.g. "1.0:\\r" "3:y".

Anything after `--` is passed to the binary rather than read as a step, which is
how you drive `luvienne <host>`:

    drive_tui.py ./target/debug/luvienne "3:y" "3:echo hi\\r" -- docker-test
"""
import fcntl, os, pty, re, select, struct, subprocess, sys, termios, time

ROWS, COLS = 40, 120

def parse_args(argv):
    """Split argv into (binary, steps, binary_args)."""
    if not argv:
        sys.exit("drive_tui: need a binary to run\n" + __doc__)
    binary, rest = argv[0], argv[1:]

    # Steps stay first so every existing invocation reads unchanged.
    if "--" in rest:
        cut = rest.index("--")
        step_args, binary_args = rest[:cut], rest[cut + 1:]
    else:
        step_args, binary_args = rest, []

    steps = []
    for arg in step_args:
        delay, sep, keys = arg.partition(":")
        # Catching this here turns the likeliest mistake — writing the host name
        # as though it were a step — into an answer rather than a traceback.
        if not sep:
            sys.exit(f"drive_tui: {arg!r} is not a delay:keys step; "
                     "arguments for the binary go after `--`")
        try:
            seconds = float(delay)
        except ValueError:
            sys.exit(f"drive_tui: {delay!r} in {arg!r} is not a number of seconds")
        steps.append((seconds, keys.encode().decode("unicode_escape")))

    return binary, steps, binary_args

def main():
    binary, steps, binary_args = parse_args(sys.argv[1:])

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    proc = subprocess.Popen(
        [binary, *binary_args], stdin=slave, stdout=slave, stderr=slave,
        close_fds=True, env={**os.environ, "TERM": "xterm-256color"},
    )
    os.close(slave)

    captured = bytearray()

    def pump(seconds):
        end = time.time() + seconds
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.05)
            if r:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                captured.extend(chunk)

    died_at = None
    for i, (delay, keys) in enumerate(steps):
        pump(delay)
        if keys:
            try:
                os.write(master, keys.encode())
            except OSError as err:
                died_at = f"step {i} ({keys!r}): {err}"
                break
    pump(2.0)

    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    # The command is echoed so a recorded run says what produced it — the same
    # steps against `luvienne` and `luvienne <host>` draw different things.
    ran = " ".join([binary, *binary_args])
    print(f"[driver] ran={ran!r} exit={proc.returncode} died_at={died_at}", file=sys.stderr)

    text = captured.decode("utf-8", "replace")
    # Strip CSI/OSC escapes so assertions run against what a human would read.
    text = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\x1b[()][B0]", "", text)
    sys.stdout.write(text)

main()

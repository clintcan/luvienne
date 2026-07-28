#!/usr/bin/env python3
"""Drive the luvienne TUI on a real pty and record what it draws.

Usage: drive_tui.py <binary> [script...]
Script steps are "delay:keys" pairs, e.g. "1.0:\\r" "3:y".
"""
import fcntl, os, pty, re, select, struct, subprocess, sys, termios, time

ROWS, COLS = 40, 120

def main():
    binary = sys.argv[1]
    steps = []
    for arg in sys.argv[2:]:
        delay, _, keys = arg.partition(":")
        steps.append((float(delay), keys.encode().decode("unicode_escape")))

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))

    proc = subprocess.Popen(
        [binary], stdin=slave, stdout=slave, stderr=slave,
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

    print(f"[driver] exit={proc.returncode} died_at={died_at}", file=sys.stderr)

    text = captured.decode("utf-8", "replace")
    # Strip CSI/OSC escapes so assertions run against what a human would read.
    text = re.sub(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"\x1b[()][B0]", "", text)
    sys.stdout.write(text)

main()

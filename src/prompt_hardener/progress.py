"""Lightweight CLI progress indicators (no external dependencies).

All output goes to stderr so it never interferes with stdout (JSON/Markdown).
When stderr is not a TTY, static lines are printed instead of animations.
"""

import sys
import threading
from typing import Optional, TextIO

_SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_INTERVAL = 0.08  # seconds between frames


class Spinner:
    """Animated spinner context manager.

    Usage::

        with Spinner("Analyzing...") as sp:
            do_work()
            sp.update("Analyzing (step 2)...")
    """

    def __init__(self, message: str = "", stream: Optional[TextIO] = None) -> None:
        self._stream = stream or sys.stderr
        self._message = message
        self._is_tty = hasattr(self._stream, "isatty") and self._stream.isatty()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # -- public API --

    def update(self, message: str) -> None:
        """Change the displayed message while the spinner is running."""
        with self._lock:
            self._message = message

    # -- context manager --

    def __enter__(self) -> "Spinner":
        if self._is_tty:
            self._thread = threading.Thread(target=self._animate, daemon=True)
            self._thread.start()
        else:
            self._static_write(self._message)
        return self

    def __exit__(self, *_exc) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
        if self._is_tty:
            # Clear the spinner line
            self._stream.write("\r\033[K")
            self._stream.flush()

    # -- internals --

    def _animate(self) -> None:
        idx = 0
        while not self._stop_event.is_set():
            frame = _SPINNER_FRAMES[idx % len(_SPINNER_FRAMES)]
            with self._lock:
                msg = self._message
            self._stream.write("\r\033[K%s %s" % (frame, msg))
            self._stream.flush()
            idx += 1
            self._stop_event.wait(_INTERVAL)

    def _static_write(self, text: str) -> None:
        self._stream.write(text + "\n")
        self._stream.flush()


class ProgressBar:
    """Simple ``[N/M] detail`` progress counter.

    Usage::

        with ProgressBar(total=10) as pb:
            for item in items:
                pb.advance("processing %s" % item)
    """

    def __init__(
        self, total: int, message: str = "", stream: Optional[TextIO] = None
    ) -> None:
        self._stream = stream or sys.stderr
        self._total = total
        self._message = message
        self._current = 0
        self._is_tty = hasattr(self._stream, "isatty") and self._stream.isatty()

    # -- public API --

    def advance(self, detail: str = "") -> None:
        """Increment the counter and update the display."""
        self._current += 1
        text = "%s[%d/%d] %s" % (
            self._message + " " if self._message else "",
            self._current,
            self._total,
            detail,
        )
        if self._is_tty:
            self._stream.write("\r\033[K%s" % text)
            self._stream.flush()
        else:
            self._stream.write(text + "\n")
            self._stream.flush()

    # -- context manager --

    def __enter__(self) -> "ProgressBar":
        return self

    def __exit__(self, *_exc) -> None:
        if self._is_tty:
            self._stream.write("\r\033[K")
            self._stream.flush()


def status_line(message: str, stream: Optional[TextIO] = None) -> None:
    """Print a single status line to stderr."""
    s = stream or sys.stderr
    s.write(message + "\n")
    s.flush()

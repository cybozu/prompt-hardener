"""Tests for progress.py – Spinner, ProgressBar, status_line."""

import io
import time

from prompt_hardener.progress import ProgressBar, Spinner, status_line


class TestSpinner:
    """Spinner tests using a non-TTY StringIO stream."""

    def test_static_output_when_not_tty(self):
        """Non-TTY stream should get a single static line (no animation)."""
        buf = io.StringIO()
        with Spinner("Loading...", stream=buf):
            pass
        output = buf.getvalue()
        assert "Loading..." in output
        assert "\n" in output  # should end with newline

    def test_update_message(self):
        """update() should change the stored message (non-TTY: only initial is printed)."""
        buf = io.StringIO()
        with Spinner("step 1", stream=buf) as sp:
            sp.update("step 2")
        output = buf.getvalue()
        # Non-TTY only prints the initial message
        assert "step 1" in output

    def test_tty_animation_runs(self):
        """When isatty() returns True, the animation thread should start."""

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        buf = FakeTTY()
        with Spinner("Working...", stream=buf):
            time.sleep(0.15)  # let a few frames render
        output = buf.getvalue()
        # After exit, spinner clears the line with \r\033[K
        assert "\r\033[K" in output

    def test_tty_update_reflected(self):
        """update() should be reflected in the animated output."""

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        buf = FakeTTY()
        with Spinner("initial", stream=buf) as sp:
            time.sleep(0.15)
            sp.update("updated")
            time.sleep(0.15)
        output = buf.getvalue()
        assert "updated" in output


class TestProgressBar:
    """ProgressBar tests using a non-TTY StringIO stream."""

    def test_advance_increments_counter(self):
        buf = io.StringIO()
        with ProgressBar(total=3, stream=buf) as pb:
            pb.advance("item-a")
            pb.advance("item-b")
            pb.advance("item-c")
        output = buf.getvalue()
        assert "[1/3] item-a" in output
        assert "[2/3] item-b" in output
        assert "[3/3] item-c" in output

    def test_message_prefix(self):
        buf = io.StringIO()
        with ProgressBar(total=2, message="Simulating", stream=buf) as pb:
            pb.advance("SIM-001")
        output = buf.getvalue()
        assert "Simulating [1/2] SIM-001" in output

    def test_tty_clears_line_on_exit(self):

        class FakeTTY(io.StringIO):
            def isatty(self):
                return True

        buf = FakeTTY()
        with ProgressBar(total=1, stream=buf) as pb:
            pb.advance("done")
        output = buf.getvalue()
        # Should end with a line clear
        assert output.endswith("\r\033[K")


class TestStatusLine:
    def test_writes_to_stream(self):
        buf = io.StringIO()
        status_line("hello world", stream=buf)
        assert buf.getvalue() == "hello world\n"

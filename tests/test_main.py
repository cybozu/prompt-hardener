import pytest

from prompt_hardener import get_version_display
from prompt_hardener.main import main, parse_args


def test_parse_args_version_subcommand():
    args = parse_args(["version"])
    assert args.command == "version"


def test_main_short_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["-v"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == get_version_display() + "\n"
    assert captured.err == ""


def test_main_long_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert captured.out == get_version_display() + "\n"
    assert captured.err == ""


def test_main_version_subcommand(capsys):
    main(["version"])

    captured = capsys.readouterr()
    assert captured.out == get_version_display() + "\n"
    assert captured.err == ""

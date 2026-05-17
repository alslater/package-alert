import pytest
from packagealert.parsers.process_args import (
    parse_pip_args,
    parse_uv_args,
    parse_npm_args,
    ParsedInstall,
)


def test_pip_install_single():
    result = parse_pip_args(["pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip_install_with_version():
    result = parse_pip_args(["pip", "install", "requests==2.31.0"])
    assert result is not None
    assert result.packages == ["requests==2.31.0"]


def test_pip_install_multiple():
    result = parse_pip_args(["pip", "install", "requests", "flask", "django==4.0"])
    assert result is not None
    assert len(result.packages) == 3


def test_pip_non_install_recognised():
    # Non-install subcommands are recognised (so venv injection fires) but carry no packages.
    result = parse_pip_args(["pip", "list"])
    assert result is not None
    assert result.packages == []

    result = parse_pip_args(["pip", "show", "requests"])
    assert result is not None
    assert result.packages == []


def test_pip_install_from_requirements_ignored():
    assert parse_pip_args(["pip", "install", "-r", "requirements.txt"]) is None


def test_uv_add():
    result = parse_uv_args(["uv", "add", "httpx"])
    assert result is not None
    assert result.packages == ["httpx"]


def test_uv_sync_returns_empty_packages():
    result = parse_uv_args(["uv", "sync"])
    assert result is not None
    assert result.packages == []


def test_uv_non_install_recognised():
    # uv run and other non-install subcommands are recognised with no packages.
    result = parse_uv_args(["uv", "run", "python"])
    assert result is not None
    assert result.packages == []


def test_npm_install_package():
    result = parse_npm_args(["npm", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_npm_install_no_args_returns_empty():
    result = parse_npm_args(["npm", "install"])
    assert result is not None
    assert result.packages == []


def test_npm_non_install_recognised():
    # npm run and other non-install subcommands are recognised with no packages.
    result = parse_npm_args(["npm", "run", "build"])
    assert result is not None
    assert result.packages == []


def test_npm_ci_returns_empty_packages():
    result = parse_npm_args(["npm", "ci"])
    assert result is not None
    assert result.packages == []


def test_pip3_recognized():
    result = parse_pip_args(["pip3", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_uv_pip_install():
    result = parse_uv_args(["uv", "pip", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_pip_full_path_recognized():
    result = parse_pip_args(["/home/user/.venv/bin/pip", "install", "requests"])
    assert result is not None
    assert result.packages == ["requests"]


def test_pip3_full_path_recognized():
    result = parse_pip_args(["/usr/bin/pip3", "install", "flask"])
    assert result is not None
    assert result.packages == ["flask"]


def test_python_m_pip_install():
    result = parse_pip_args(["python3", "-m", "pip", "install", "django"])
    assert result is not None
    assert result.packages == ["django"]


def test_python_full_path_m_pip_install():
    result = parse_pip_args(["/usr/bin/python3", "-m", "pip", "install", "numpy"])
    assert result is not None
    assert result.packages == ["numpy"]


def test_uv_full_path_recognized():
    result = parse_uv_args(["/home/user/.cargo/bin/uv", "add", "httpx"])
    assert result is not None
    assert result.packages == ["httpx"]


def test_npm_full_path_recognized():
    result = parse_npm_args(["/usr/local/bin/npm", "install", "lodash"])
    assert result is not None
    assert result.packages == ["lodash"]


def test_python_script_pip_install():
    # python /path/to/venv/bin/pip install <pkg>  — the exact pattern that was missed
    result = parse_pip_args([
        "/home/aslate/tmp/test/venv/bin/python",
        "/home/aslate/tmp/test/venv/bin/pip",
        "install",
        "opencv-python",
    ])
    assert result is not None
    assert result.packages == ["opencv-python"]

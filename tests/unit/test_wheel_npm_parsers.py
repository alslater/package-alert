import io
import json
import tarfile
import zipfile

from packagealert.parsers.npm import inspect_npm_tarball, parse_package_json_file
from packagealert.parsers.wheel import parse_wheel_filename, read_wheel_metadata

# --- Wheel tests ---

def test_parse_simple_wheel(tmp_path):
    p = tmp_path / "requests-2.31.0-py3-none-any.whl"
    p.touch()
    info = parse_wheel_filename(p)
    assert info is not None
    assert info.name == "requests"
    assert info.version == "2.31.0"


def test_parse_wheel_normalizes_underscores(tmp_path):
    p = tmp_path / "my_package-1.0.0-py3-none-any.whl"
    p.touch()
    info = parse_wheel_filename(p)
    assert info is not None
    assert info.name == "my-package"


def test_parse_invalid_filename_returns_none(tmp_path):
    p = tmp_path / "notawheel.tar.gz"
    p.touch()
    assert parse_wheel_filename(p) is None


def test_read_wheel_metadata(tmp_path):
    wheel_path = tmp_path / "mypkg-1.0.0-py3-none-any.whl"
    # Create a minimal valid wheel (zip) with METADATA
    with zipfile.ZipFile(wheel_path, "w") as zf:
        zf.writestr("mypkg-1.0.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: mypkg\nVersion: 1.0.0\n\nBody")
    meta = read_wheel_metadata(wheel_path)
    assert meta.get("Name") == "mypkg"
    assert meta.get("Version") == "1.0.0"


def test_read_wheel_metadata_nonexistent(tmp_path):
    result = read_wheel_metadata(tmp_path / "missing.whl")
    assert result == {}


# --- npm tests ---

def test_parse_package_json_file(tmp_path):
    pkg = {
        "name": "express",
        "version": "4.18.0",
        "scripts": {"test": "jest", "postinstall": "node setup.js"},
    }
    p = tmp_path / "package.json"
    p.write_text(json.dumps(pkg))
    info = parse_package_json_file(p)
    assert info is not None
    assert info.name == "express"
    assert info.version == "4.18.0"
    assert info.has_install_script is True


def test_parse_package_json_no_install_script(tmp_path):
    pkg = {"name": "lodash", "version": "4.17.21", "scripts": {"test": "jest"}}
    p = tmp_path / "package.json"
    p.write_text(json.dumps(pkg))
    info = parse_package_json_file(p)
    assert info is not None
    assert info.has_install_script is False


def test_inspect_npm_tarball(tmp_path):
    pkg_json = json.dumps({"name": "lodash", "version": "4.17.21", "scripts": {}}).encode()
    tgz_path = tmp_path / "lodash-4.17.21.tgz"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(pkg_json)
        tf.addfile(info, io.BytesIO(pkg_json))
    tgz_path.write_bytes(buf.getvalue())
    result = inspect_npm_tarball(tgz_path)
    assert result is not None
    assert result.name == "lodash"
    assert result.version == "4.17.21"

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


def test_parse_wheel_compound_platform_tag(tmp_path):
    """The platform tag may itself contain dots — a manylinux wheel
    commonly ships as two platform tags joined by a dot (e.g.
    "manylinux_2_17_x86_64.manylinux2014_x86_64"), a common shape for any
    package with a compiled extension (cryptography, numpy, etc.), and
    must still parse.
    """
    p = tmp_path / "cryptography-42.0.0-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
    p.touch()
    info = parse_wheel_filename(p)
    assert info is not None
    assert info.name == "cryptography"
    assert info.version == "42.0.0"


def test_parse_invalid_filename_returns_none(tmp_path):
    p = tmp_path / "notawheel.tar.gz"
    p.touch()
    assert parse_wheel_filename(p) is None


def test_parse_wheel_treats_backup_suffixed_file_as_a_compound_platform_tag(tmp_path):
    """A backup/copy of a real wheel named like
    "requests-2.31.0-py3-none-any.whl.backup.whl" is lexically
    indistinguishable, under real PEP 425 character-class rules, from a
    wheel whose platform field is an unusual 3-component compressed tag
    ("any.whl.backup") — there is no valid tag-content rule that can tell
    the two apart, so this parser does not attempt one; it parses as a
    wheel, reporting the SAME (name, version) the genuine wheel already
    would. See test_parse_wheel_does_not_reject_a_real_whl_platform_tag
    for why rejecting this shape via a reserved word is unsafe instead.
    """
    p = tmp_path / "requests-2.31.0-py3-none-any.whl.backup.whl"
    p.touch()
    info = parse_wheel_filename(p)
    assert info is not None
    assert info.name == "requests"
    assert info.version == "2.31.0"


def test_parse_wheel_does_not_reject_a_real_whl_platform_tag(tmp_path):
    """Regression: an earlier version of this parser excluded any tag
    component literally equal to "whl", to reject the backup-suffix
    shape above — but PEP 425 places no constraint on tag CONTENT beyond
    its character set, and package authors control their own wheel
    filenames, so a real wheel whose platform (or python/abi) tag
    happens to be the literal word "whl" is syntactically legitimate.
    Reserving it made such a wheel fail to parse at all — a real
    cache-detection bypass, confirmed empirically, not just a missed
    edge case: a malicious package could ship a wheel using this exact
    tag to silently evade this parser entirely.
    """
    p = tmp_path / "malicious-1.0.0-py3-none-whl.whl"
    p.touch()
    info = parse_wheel_filename(p)
    assert info is not None
    assert info.name == "malicious"
    assert info.version == "1.0.0"


def test_parse_wheel_compound_python_tag(tmp_path):
    """A wheel satisfying more than one Python version ships a compressed
    python tag like "py2.py3" (dot-joined, per PEP 425) — the same
    compound-tag shape platform supports (see
    test_parse_wheel_compound_platform_tag) must parse for python too.
    """
    p = tmp_path / "six-1.16.0-py2.py3-none-any.whl"
    p.touch()
    info = parse_wheel_filename(p)
    assert info is not None
    assert info.name == "six"
    assert info.version == "1.16.0"


def test_parse_wheel_rejects_non_pep425_characters_in_python_or_abi_tag(tmp_path):
    """A malformed cache filename containing a non-tag character (e.g. "@")
    in the python or abi field must be rejected, not parsed as a false
    package event — those fields are restricted to real PEP 425 tag
    characters just like platform is.
    """
    for name in [
        "requests-2.31.0-py3@-none-any.whl",
        "requests-2.31.0-py3-none@-any.whl",
    ]:
        p = tmp_path / name
        p.touch()
        assert parse_wheel_filename(p) is None, f"expected {name!r} to be rejected"


def test_parse_wheel_rejects_a_trailing_newline(tmp_path):
    r"""The PEP 427 filename pattern is anchored with \Z, not $.

    Python's $ also matches immediately before a final newline, and Linux
    permits newlines in filenames (only "/" and NUL are banned), so a
    $-anchored pattern would accept "pkg-1.0-py3-none-any.whl\n" as a
    valid wheel and report a package that was never installed. Asserts
    both directions: the newline form is rejected AND the plain form
    still parses.
    """
    genuine = "requests-2.31.0-py3-none-any.whl"

    plain = tmp_path / genuine
    plain.touch()
    info = parse_wheel_filename(plain)
    assert info is not None, "the plain filename must still parse"
    assert (info.name, info.version) == ("requests", "2.31.0")

    newline = tmp_path / (genuine + "\n")
    newline.touch()
    assert parse_wheel_filename(newline) is None, (
        "a filename with a trailing newline must not parse as a wheel"
    )


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

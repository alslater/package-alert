from __future__ import annotations

from unittest.mock import patch

from typer.testing import CliRunner

from packagealert.cli.app import app

runner = CliRunner()


def test_version_cmd_prints_version():
    with patch("packagealert.cli.app._pkg_version", return_value="1.2.3"):
        result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "1.2.3" in result.output

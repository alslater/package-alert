from __future__ import annotations

from typer.testing import CliRunner
from unittest.mock import AsyncMock, patch

runner = CliRunner()


def test_cooldown_allow_blocked_by_policy(tmp_path):
    from packagealert.cli.app import app
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("[sandbox.cooldown]\nallow_cooldown_allow = false\n")
    # Patch the veto so the supplied config is always used regardless of default plugins.
    with patch("packagealert.cli.app._apply_config_veto", side_effect=lambda c, *_: c):
        result = runner.invoke(app, ["cooldown", "allow", "requests", "2.31.0", "--config", str(cfg_file)])
    assert result.exit_code != 0
    assert "disabled by policy" in result.output.lower() or "disabled" in result.output.lower()


def test_cooldown_allow_permitted_by_default(tmp_path):
    from packagealert.cli.app import app
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("")

    with patch("packagealert.cli.app._apply_config_veto", side_effect=lambda c, *_: c), \
         patch("packagealert.storage.db.open_db", new_callable=AsyncMock) as mock_open_db, \
         patch("packagealert.storage.db.store_cooldown_cleared", new_callable=AsyncMock) as mock_store:
        mock_db = AsyncMock()
        mock_db.close = AsyncMock()
        mock_open_db.return_value = mock_db
        mock_store.return_value = None

        result = runner.invoke(app, ["cooldown", "allow", "requests", "2.31.0", "--config", str(cfg_file)])
    assert result.exit_code == 0

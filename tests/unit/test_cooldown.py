import asyncio
import time
from unittest.mock import MagicMock

import pytest
from packagealert.languages.base import PackageSpec
from packagealert.storage.db import open_db


def test_publication_cache_table_exists(tmp_path):
    db_path = tmp_path / "test.db"
    async def _check():
        db = await open_db(db_path)
        async with db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='publication_cache'"
        ) as cur:
            row = await cur.fetchone()
        await db.close()
        return row
    row = asyncio.run(_check())
    assert row is not None


def test_cooldown_cleared_table_exists(tmp_path):
    db_path = tmp_path / "test.db"
    async def _check():
        db = await open_db(db_path)
        async with db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cooldown_cleared'"
        ) as cur:
            row = await cur.fetchone()
        await db.close()
        return row
    row = asyncio.run(_check())
    assert row is not None


def _make_cfg(period_days=7, on_new_medium_risk="prompt", on_new_low_risk="warn", non_interactive_escalation="block"):
    from packagealert.config import CooldownConfig
    return CooldownConfig(
        period_days=period_days,
        on_new_medium_risk=on_new_medium_risk,
        on_new_low_risk=on_new_low_risk,
        non_interactive_escalation=non_interactive_escalation,
    )


def _pkg(name="requests", version="2.31.0", ecosystem="PyPI"):
    return PackageSpec(name=name, version=version, ecosystem=ecosystem)


class TestCooldownDecisionAge:
    def test_within_period_medium_risk_prompts(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=3.0, risk_score=45, cfg=_make_cfg(), is_tty=True)
        assert decision.action == "prompt"

    def test_within_period_low_risk_warns(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=3.0, risk_score=0, cfg=_make_cfg(), is_tty=True)
        assert decision.action == "warn"

    def test_beyond_period_allows(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=10.0, risk_score=0, cfg=_make_cfg(), is_tty=True)
        assert decision.action == "allow"

    def test_at_boundary_allows(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=7.0, risk_score=0, cfg=_make_cfg(), is_tty=True)
        assert decision.action == "allow"

    def test_no_date_warns_and_allows(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=None, risk_score=0, cfg=_make_cfg(), is_tty=True)
        assert decision.action == "warn"

    def test_non_interactive_prompt_escalates_to_block(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=3.0, risk_score=45, cfg=_make_cfg(), is_tty=False)
        assert decision.action == "block"

    def test_non_interactive_warn_unchanged(self):
        from packagealert.sandbox.cooldown import decide
        decision = decide(_pkg(), age_days=3.0, risk_score=0, cfg=_make_cfg(), is_tty=False)
        assert decision.action == "warn"


class TestCooldownCleared:
    def test_cleared_within_period_allows(self):
        from packagealert.sandbox.cooldown import decide_with_cleared
        pkg = _pkg()
        cfg = _make_cfg(period_days=7)
        cleared_at = time.time() - (3 * 86400)  # 3 days ago
        decision = decide_with_cleared(
            pkg, age_days=3.0, risk_score=0, cfg=cfg, is_tty=True,
            cleared_at=cleared_at,
        )
        assert decision.action == "allow"

    def test_cleared_expired_re_prompts(self):
        from packagealert.sandbox.cooldown import decide_with_cleared
        pkg = _pkg()
        cfg = _make_cfg(period_days=7)
        cleared_at = time.time() - (8 * 86400)  # 8 days ago — expired
        decision = decide_with_cleared(
            pkg, age_days=3.0, risk_score=45, cfg=cfg, is_tty=True,
            cleared_at=cleared_at,
        )
        assert decision.action == "prompt"


class TestPublicationCacheDB:
    def test_store_and_fetch_publication_date(self, tmp_path):
        import asyncio
        import time
        from packagealert.storage.db import open_db, store_publication_date, get_publication_date
        pub_time = time.time() - (3 * 86400)

        async def _run():
            db = await open_db(tmp_path / "test.db")
            await store_publication_date(db, ecosystem="PyPI", package="requests", version="2.31.0", published_at=pub_time)
            result = await get_publication_date(db, ecosystem="PyPI", package="requests", version="2.31.0")
            await db.close()
            return result

        result = asyncio.run(_run())
        assert result == pytest.approx(pub_time)

    def test_not_found_cached_as_none(self, tmp_path):
        import asyncio
        from packagealert.storage.db import open_db, store_publication_date, get_publication_date

        async def _run():
            db = await open_db(tmp_path / "test.db")
            await store_publication_date(db, ecosystem="PyPI", package="ghost", version="1.0.0", published_at=None)
            result = await get_publication_date(db, ecosystem="PyPI", package="ghost", version="1.0.0")
            await db.close()
            return result

        result = asyncio.run(_run())
        assert result == "not_found"

    def test_cache_miss_returns_sentinel(self, tmp_path):
        import asyncio
        from packagealert.storage.db import open_db, get_publication_date

        async def _run():
            db = await open_db(tmp_path / "test.db")
            result = await get_publication_date(db, ecosystem="PyPI", package="unknown", version="9.9.9")
            await db.close()
            return result

        result = asyncio.run(_run())
        assert result == "miss"


class TestCooldownClearedDB:
    def test_store_and_fetch_cleared(self, tmp_path):
        import asyncio
        import time
        from packagealert.storage.db import open_db, store_cooldown_cleared, get_cooldown_cleared_at

        async def _run():
            db = await open_db(tmp_path / "test.db")
            await store_cooldown_cleared(db, ecosystem="PyPI", package="requests", version="2.31.0")
            result = await get_cooldown_cleared_at(db, ecosystem="PyPI", package="requests", version="2.31.0")
            await db.close()
            return result

        result = asyncio.run(_run())
        assert result is not None
        assert result == pytest.approx(time.time(), abs=5)

    def test_miss_returns_none(self, tmp_path):
        import asyncio
        from packagealert.storage.db import open_db, get_cooldown_cleared_at

        async def _run():
            db = await open_db(tmp_path / "test.db")
            result = await get_cooldown_cleared_at(db, ecosystem="PyPI", package="nothing", version="0.0.1")
            await db.close()
            return result

        result = asyncio.run(_run())
        assert result is None


class TestFetchPublicationDate:
    def test_pypi_parses_upload_time(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch
        from packagealert.sandbox.cooldown import fetch_publication_date

        pypi_response = {
            "urls": [
                {"upload_time": "2024-01-10T12:00:00"},
                {"upload_time": "2024-01-10T11:00:00"},
                {"upload_time": "2024-01-10T13:00:00"},
            ]
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = pypi_response

        async def _run():
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                return await fetch_publication_date("https://pypi.org/pypi/requests/2.31.0/json", ecosystem="PyPI")

        result = asyncio.run(_run())
        from datetime import datetime, timezone
        expected = datetime(2024, 1, 10, 11, 0, 0, tzinfo=timezone.utc).timestamp()
        assert result == pytest.approx(expected, abs=1)

    def test_returns_none_on_network_error(self):
        import asyncio
        import httpx
        from unittest.mock import AsyncMock, patch
        from packagealert.sandbox.cooldown import fetch_publication_date

        async def _run():
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(side_effect=httpx.ConnectError("timeout"))
                return await fetch_publication_date("https://pypi.org/pypi/x/1.0/json", ecosystem="PyPI")

        result = asyncio.run(_run())
        assert result is None

    def test_returns_not_found_on_404(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock, patch
        from packagealert.sandbox.cooldown import fetch_publication_date

        mock_resp = MagicMock()
        mock_resp.status_code = 404

        async def _run():
            with patch("httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)
                mock_client.get = AsyncMock(return_value=mock_resp)
                return await fetch_publication_date("https://pypi.org/pypi/ghost/9.9/json", ecosystem="PyPI")

        result = asyncio.run(_run())
        assert result == "not_found"

from __future__ import annotations

import re
from dataclasses import dataclass

from Levenshtein import distance as levenshtein_distance

# Top PyPI packages by download count (static list)
_TOP_PYPI = [
    "requests", "boto3", "urllib3", "botocore", "setuptools", "pip", "certifi",
    "charset-normalizer", "idna", "s3transfer", "six", "python-dateutil", "pyyaml",
    "numpy", "packaging", "typing-extensions", "attrs", "cryptography", "cffi",
    "click", "flask", "django", "fastapi", "pydantic", "sqlalchemy", "celery",
    "pillow", "pandas", "scipy", "matplotlib", "pytest", "mypy", "black", "isort",
    "httpx", "aiohttp", "starlette", "uvicorn", "gunicorn", "paramiko", "fabric",
    "ansible", "docker", "kubernetes", "boto", "awscli", "google-cloud-storage",
    "google-auth", "azure-storage-blob", "psycopg2", "pymongo", "redis",
    "elasticsearch", "twisted", "werkzeug", "jinja2", "markupsafe", "itsdangerous",
    "pygments", "colorama", "tqdm", "rich", "typer", "pydantic-settings",
]

# Top npm packages
_TOP_NPM = [
    "lodash", "express", "react", "react-dom", "axios", "moment", "chalk",
    "commander", "yargs", "webpack", "babel-core", "eslint", "typescript",
    "jest", "mocha", "nodemon", "dotenv", "cors", "body-parser", "mongoose",
    "sequelize", "socket.io", "passport", "jsonwebtoken", "bcrypt", "multer",
    "uuid", "debug", "async", "underscore", "bluebird", "request", "node-fetch",
    "cross-env", "concurrently", "prettier", "husky", "lint-staged", "pm2",
    "next", "nuxt", "vue", "angular", "svelte", "gatsby", "webpack-cli",
    "babel-loader", "css-loader", "style-loader", "mini-css-extract-plugin",
]

_TYPO_THRESHOLD = 2  # max Levenshtein distance to flag

# Thresholds for low-popularity compound signal
_LOW_VERSION_COUNT = 5
_LOW_DEPENDENT_COUNT = 10


@dataclass
class TyposquatResult:
    is_typosquat: bool
    closest_match: str | None
    distance: int | None
    score: int  # risk signal score (0 if not typosquat)


class TyposquatDetector:
    def __init__(self) -> None:
        self._pypi_packages = set(_TOP_PYPI)
        self._npm_packages = set(_TOP_NPM)

    async def analyze(self, name: str, ecosystem: str) -> TyposquatResult:
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        candidates = self._pypi_packages if ecosystem == "pypi" else self._npm_packages

        # Exact match — not a typosquat
        if normalized in candidates:
            return TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)

        best_match: str | None = None
        best_dist = _TYPO_THRESHOLD + 1

        for candidate in candidates:
            d = levenshtein_distance(normalized, candidate)
            if d < best_dist:
                best_dist = d
                best_match = candidate

        if best_dist <= _TYPO_THRESHOLD and best_match:
            score = 20 if best_dist == 1 else 15
            return TyposquatResult(
                is_typosquat=True,
                closest_match=best_match,
                distance=best_dist,
                score=score,
            )

        return TyposquatResult(is_typosquat=False, closest_match=None, distance=None, score=0)

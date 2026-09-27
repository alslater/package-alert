from __future__ import annotations

from pydantic import BaseModel, computed_field


class OsvAdvisory(BaseModel):
    model_config = {"frozen": False}

    id: str
    summary: str
    details: str | None = None
    severity: str | None = None
    aliases: list[str] = []
    fixed_versions: list[str] = []

    @computed_field
    @property
    def is_malicious(self) -> bool:
        return self.id.startswith("MAL-") or any(a.startswith("MAL-") for a in self.aliases)


class OsvResult(BaseModel):
    package_name: str
    ecosystem: str
    version: str | None
    advisories: list[OsvAdvisory] = []
    degraded: bool = False
    """True when this result is NOT a complete answer, so absences prove nothing.

    A failed lookup yields an advisory-free OsvResult, and without this flag
    that is indistinguishable from a genuine "no advisories for this package"
    answer — every other field is identical. This flag is the only thing that
    separates them, so a consumer reading `advisories` alone still cannot tell
    "checked, clean" from "never actually checked".

    A degraded result is not necessarily EMPTY: when some of a package's vulns
    parse and others do not, the ones that parsed are kept (see
    _parse_vulns()). Those are authoritative positives, so a consumer must act
    on `has_malicious` BEFORE — never instead of — treating the result as
    unchecked; gating on `degraded` first fails open on a real MAL- advisory.

    OsvClient sets it for every way a lookup can fail to produce an
    authoritative verdict:

    - exhausted 429/503 retries, or a RequestError (the network never
      reached OSV);
    - a non-retryable HTTP status (4xx/5xx other than 429/503);
    - a 200 whose body is unparseable, or is valid JSON that is not an
      object;
    - a 200 whose result count does not match the query count, which
      destroys the positional pairing verdicts depend on, so the whole
      response degrades;
    - a 200 that is well-formed overall but malformed for ONE result (a
      non-list "vulns"), which degrades only that package and leaves its
      siblings authoritative;
    - a result with at least one malformed vuln (no "id", a field failing
      validation), which keeps every advisory that did parse and marks only
      that result partial.

    Callers must never persist a degraded result as a verdict: doing so
    caches an OSV outage as "clean" for the whole osv_cache TTL, so a
    genuinely malicious package installed during the outage is never
    re-queried once OSV recovers. They must also not REPORT one as clean —
    an empty advisory list here means "unknown", not "safe".
    """

    @property
    def has_malicious(self) -> bool:
        return any(a.is_malicious for a in self.advisories)

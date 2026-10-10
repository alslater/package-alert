"""A package manager's dependency graph, as the fix planner needs it."""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class DependencyGraph:
    """Names are each manager's canonical spelling (PEP 503 for Python)."""

    members: frozenset[str]
    """The project's own packages (workspace members); never upgrade targets."""
    direct: frozenset[str]
    """Third-party names some member declares, in any dependency group."""
    deps: Mapping[str, frozenset[str]]
    """name -> the names it depends on, inapplicable-marker edges dropped."""
    versions: Mapping[str, frozenset[str]]
    """name -> every version locked for it, across all marker forks."""
    non_registry: frozenset[str]
    """Names locked from a git, URL or path source: no registry version to pin."""
    aliased: frozenset[str] = frozenset()
    """Names installed under another name (npm's "alias": "npm:name@range"): a pin
    by the real name would add a new dependency rather than move the alias."""

    def path_to(self, name: str) -> list[str]:
        """The shortest chain from a member to *name*, both ends included.

        [] when no member reaches it. Ties are broken by name, so the result
        is stable across runs.
        """
        if name in self.members:
            return [name]
        prev: dict[str, str | None] = {m: None for m in self.members}
        queue = deque(sorted(self.members))
        while queue:
            cur = queue.popleft()
            for nxt in sorted(self.deps.get(cur, ())):
                if nxt in prev:
                    continue
                prev[nxt] = cur
                if nxt == name:
                    chain = [nxt]
                    step: str | None = cur
                    while step is not None:
                        chain.append(step)
                        step = prev[step]
                    return chain[::-1]
                queue.append(nxt)
        return []

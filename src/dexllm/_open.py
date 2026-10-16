"""Open a session the way the servers do: strict first, lenient on refusal.

dexllm#112. The MCP server and the HTTP ``/upload`` endpoint take a single
path from a caller who cannot pass ``lenient=True`` themselves, and a sample the
strict verifier refuses — a post-build string swap ART would also refuse, or a
partially-decrypted dump — is exactly what an analyst points them at. So both
try ``DexKit(path)`` and fall back to ``DexKit([path], lenient=True)``, and SAY
so. One definition, so the two servers cannot drift.

"Refused" has TWO shapes, and the first cut handled only one. A source whose
every dex fails raises. A container whose SIBLING dex verifies does not: the
survivors load (dexllm#25) and the failed dex is just a ``valid: False`` row —
which is the realistic shape (an app's ``classes.dex`` carries the swap, its
``classes2.dex`` does not), and silently dropping the main dex is the worst
answer. So a strict session with a rejected row is retried too, and the lenient
one is taken only when it loads MORE dexes.
"""

from __future__ import annotations

from ._dexkit_core import DexKit


def _rejections(dk: DexKit) -> list[str]:
    return [f"{r['name']}: {r['reason']}" for r in dk.verify_report() if not r["valid"]]


def open_strict_then_lenient(path: str) -> tuple[DexKit, str]:
    """Return ``(session, strict_refusal)``.

    ``strict_refusal`` is ``""`` when the strict session is used, else what the
    strict verifier refused — the exception (``"<Type>: <message>"``) or the
    rejected dexes (``"<name>: <reason>"``, ``"; "``-joined) — that the lenient
    session was opened after. If neither mode loads, the STRICT error is raised:
    it is the one a caller who never asked for leniency expects.
    """
    try:
        strict = DexKit(path)
    except RuntimeError as err:
        try:
            dk = DexKit([path], lenient=True)
        except RuntimeError:
            raise err from None
        return dk, f"{type(err).__name__}: {err}"
    refused = _rejections(strict)
    if not refused:
        return strict, ""
    try:
        lenient = DexKit([path], lenient=True)
    except RuntimeError:
        return strict, ""
    if lenient.dex_count() <= strict.dex_count():
        return strict, ""
    return lenient, "; ".join(refused)

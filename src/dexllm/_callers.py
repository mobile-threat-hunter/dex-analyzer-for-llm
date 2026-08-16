"""What counts as a bundled-library caller — ONE definition, shared.

:func:`dexllm.dangerous_permission_api_callers` and
:func:`dexllm.summarize_capabilities` both answer "is this the app's own
behaviour or library plumbing", and they must answer it the same way. Keeping
the predicate here rather than in either module makes that structural: the two
cannot drift into different notions of "a bundled library".

**The blind spots are stated here rather than discovered.** A prefix list is a
heuristic over the caller's package name, so it is wrong in two directions:

* a library **shaded** under the app's own package (or minified into one, which
  is what R8 does to a repackaged build) reads as app code and is KEPT;
* code that merely *sits* under one of these prefixes reads as a library and is
  DROPPED — which is exactly what a repackaged sample does when it hides under
  ``com.google.android.*``.

The second direction is the one that hides a finding, so a caller-filtered
report is a triage aid, not a proof of absence: ``app_only=False`` (both APIs)
returns every caller, and ``by_caller`` / ``callers`` name them.

**Not to be confused with** ``dexllm.is_framework_descriptor`` (the C++
``kFrameworkPrefixes``), which answers a different question — "is this
REFERENCED TYPE framework code", behind ``list_external_*(framework_only=)`` —
over a deliberately different set: it carries ``Landroid/`` / ``Lorg/json/`` /
``Lsun/`` / ``Llibcore/`` and NOT ``Landroidx/``, so it calls
``Landroidx/core/app/ActivityCompat;`` a non-framework type while the predicate
here calls it a bundled-library caller. Both are right for their own question.
"""

from __future__ import annotations

# Caller classes that are bundled framework / official-library code. A sensitive
# API call from here is library plumbing (e.g. androidx permission helpers,
# Play-services location) rather than the app's own behaviour — `app_only`
# filters them out. Descriptor-prefix form for cheap caller_descriptor matching.
_FRAMEWORK_CALLER_PREFIXES = (
    "Landroidx/",
    "Landroid/support/",
    "Landroid/arch/",
    "Lkotlin/",
    "Lkotlinx/",
    "Ljava/",
    "Ljavax/",
    "Ldalvik/",
    "Lcom/google/android/",
    "Lcom/google/common/",
    "Lcom/google/gson/",
)


def _is_framework_caller(descriptor: str) -> bool:
    """Return True if a caller belongs to bundled framework / official-library code."""
    return descriptor.startswith(_FRAMEWORK_CALLER_PREFIXES)

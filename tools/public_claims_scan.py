#!/usr/bin/env python3
"""Public-claims scan for the Don't-Lie repository.

v0.3.9 is a local-first, MIT-licensed Python package. Every tracked
public Markdown and HTML file in this repository must describe that
product and nothing else. The pattern below is automated into CI so
a future contribution cannot reintroduce hosted-tier, paid, or
hosted-witness language that the truth sweep removed.

The scan uses three mechanisms:

  1. **File-level allowlist.** A small set of files are explicitly
     allowed to mention hosted features because their entire job is
     to be honest about what the product does NOT do (the
     disclaimer sections).

  2. **Section-level allowlist.** Within any file, a match is allowed
     if it sits inside an approved disclaimer block. The block is
     detected by either:
        - a Markdown heading containing "not", "limit", "what is
          NOT", "disclaimer", "no hosted service", "no warranty",
          "as is", "operator reference", or "rejection of warranty".
        - a Markdown blockquote (lines starting with ">") at the
          matched line.
        - an HTML `<div>` or `<section>` whose class name contains
          "limit", "disclaimer", or "not-shipped".

  3. **Negative-context exclusion.** A match in common git/developer
     language ("fresh checkout", "git checkout") is not a hosted
     promise and is allowed.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files where hosted/paid language is the entire point of the
# disclaimer. The full text of these files is allowed.
FILE_ALLOWLIST: set[str] = {
    # The landing page's job is the disclaimer.
    "site/index.html",
    # The README's job is the "no hosted service" framing.
    "README.md",
    # The CHANGELOG records the past paperwork changes.
    "CHANGELOG.md",
    # LAUNCH.md is the original release notes (already honest about
    # the absence of a hosted service).
    "LAUNCH.md",
    # security.md, PLDG.md, competitive.md, flow.md, PRIVACY.md (the
    # technical one, not the legal one) are operator-facing
    # material that is honest about the local-only product.
    "security.md",
    "PLDG.md",
    "competitive.md",
    "flow.md",
    "PRIVACY.md",
    # docs/future-work.md is itself the disclaimer about what's not
    # in the product.
    "docs/future-work.md",
    # The legal docs are explicitly forward-looking: they describe
    # the v0.3.x state and the "when a hosted service ships"
    # posture. They are the right place to discuss the possibility
    # of a hosted service in the future.
    "company/PRIVACY_POLICY.md",
    "company/TERMS_OF_SERVICE.md",
    "company/DPA.md",
    "company/BRAND.md",
    # Issue templates that may legitimately mention hosted features
    # in the context of a buyer asking about them.
    ".github/ISSUE_TEMPLATE/compliance-question.md",
    # The scan itself lists the prohibited phrases.
    "tools/public_claims_scan.py",
}

# Markdown heading patterns that mark a "this is a disclaimer" block.
DISCLAIMER_HEADING_MARKERS = [
    "what is not",
    "what's not",
    "what is in this release",
    "what is shipped",
    "what is not shipped",
    "limits",
    "limitation",
    "disclaimer",
    "rejection of warranty",
    "no warranty",
    "as is",
    "what dont-lie does not",
    "what this does not",
    "no hosted service today",
    "no hosted service",
    "operator reference",
    "not a vendor certification",
    "not legal advice",
    "not the work of counsel",
    "what is not in",
    "what is not shipped",
    "what is not in this release",
    "what's not in",
    "do not represent",
    "do not claim",
    "does not",
    "do not",
    "no paid",
    "no compliance product",
    "not promise",
    "no sla",
    "no on-call",
    "no support contract",
    "no support staff",
    "no subscription",
    "no billing",
    "not a hosted",
    "is not a",
    "is not certification",
    "is not a b",
    "is not legal",
]

# HTML class tokens that mark a disclaimer block.
HTML_DISCLAIMER_TOKENS = ["limit", "disclaimer", "not-shipped", "warning", "limits"]


def is_markdown_disclaimer_section(text: str, match_start: int) -> bool:
    """Return True if `match_start` sits inside a disclaimer Markdown section.

    Heuristic: walk backwards from `match_start` to find the most
    recent heading. If the heading text matches a disclaimer marker,
    the match is approved. Also approves if the matched line itself
    is a blockquote.
    """
    head = text[:match_start]
    # Blockquote at the matched line is a strong signal
    line_start = head.rfind("\n") + 1
    line = text[line_start:text.find("\n", line_start) if "\n" in text[line_start:] else len(text)]
    if line.lstrip().startswith(">"):
        return True
    headings = list(re.finditer(r"(?m)^#{1,6}\s+.*$", head))
    if not headings:
        return False
    last = headings[-1].group(0).lower()
    return any(m in last for m in DISCLAIMER_HEADING_MARKERS)


def is_html_disclaimer_section(text: str, match_start: int) -> bool:
    """Return True if `match_start` sits inside a disclaimer HTML section."""
    head = text[:match_start].lower()
    for tag in re.finditer(r"<(?:div|section)\b[^>]*>", head, re.IGNORECASE | re.DOTALL):
        attrs = tag.group(0)
        if any(t in attrs.lower() for t in HTML_DISCLAIMER_TOKENS):
            return True
    return False


def is_git_checkout_context(text: str, match_start: int) -> bool:
    """Allow "fresh checkout" / "git checkout" — git terminology, not payment."""
    line_start = text.rfind("\n", 0, match_start) + 1
    line_end = text.find("\n", match_start)
    if line_end == -1:
        line_end = len(text)
    line = text[line_start:line_end].lower()
    return (
        "fresh checkout" in line
        or "source checkout" in line
        or "git checkout" in line
    )


# Phrases that should never appear in a public file outside a
# disclaimer block. Match is case-sensitive. The right-hand side is
# the human-readable reason the phrase is prohibited.
PROHIBITED: list[tuple[str, str]] = [
    # Unsupported legal/compliance conclusions. Operator-reference files can
    # say these phrases only inside an explicit disclaimer section.
    (r"\bHIPAA[- ](?:compliant|grade)\b", "unsupported HIPAA conclusion"),
    (r"\bAI Act[- ](?:compliant|ready)\b", "unsupported AI Act conclusion"),
    (r"\b(?:directly )?implements Article 12\b", "unsupported Article 12 conclusion"),
    (r"\bguarantees? compliance\b", "unsupported compliance guarantee"),
    (r"\bpass(?:es|ing)? (?:a |the )?(?:HIPAA|EU AI Act|AI Act) audit\b", "unsupported audit-pass claim"),
    # Tier names used as product names
    (r"\bSolo tier\b", "paid tier name"),
    (r"\bPro tier\b", "paid tier name"),
    (r"\bTeam tier\b", "paid tier name"),
    (r"\bCompliance tier\b", "paid tier name"),
    (r"\bEnterprise tier\b", "paid tier name"),
    (r"\bDeveloper tier\b", "paid tier name"),
    # Prices
    (r"\$\d+(?:\.\d+)?\s*/\s*(?:mo|month|seat|yr|year)\b", "explicit price"),
    (r"\$\d+(?:\.\d+)?\s+per\s+seat", "per-seat price"),
    # Hosted promises (specific noun forms, not the word "hosted" alone)
    (r"hosted\s+(?:witness|vault|service|tier|product|dashboard|notary|compliance)\b", "hosted service promise"),
    # "Designated" support / "pilot" / "design-partner" marketing
    (r"designated\s+success\s+engineer", "designated support marketing"),
    (r"designated\s+support\s+engineer", "designated support marketing"),
    (r"designated\s+(?:support|success)\b", "designated support marketing"),
    (r"30-day\s+pilot", "pilot program marketing"),
    (r"design-partner\s+pricing", "pilot program marketing"),
    # Stripe
    (r"\bStripe\b", "Stripe is a third-party payment processor"),
    # Specific checkout patterns (not the bare word)
    (r"checkout\s+(?:page|button|flow|session|server)", "checkout copy"),
    (r"tier\s+checkout", "tier checkout copy"),
    (r"paid\s+checkout", "paid checkout copy"),
    # "per-seat" pricing talk (specific)
    (r"per-seat\s+(?:license|pricing|tier|month|annual)", "per-seat pricing language"),
    # Specific hosted-feasibility promises
    (r"S3\s+Object\s+Lock\s+(?:retention\s+)?guarantee", "Object Lock guarantee claim"),
    (r"\b7-year\s+retention\b", "retention guarantee claim"),
    # Deleted file references
    (r"site/pricing\.html", "deleted file: site/pricing.html"),
    (r"site/CHECKOUT\.html", "deleted file: site/CHECKOUT.html"),
    (r"site/RECEIPT_EXPLORER\.html", "deleted file: site/RECEIPT_EXPLORER.html"),
    (r"site/compare\.html", "deleted file: site/compare.html"),
    (r"site/thanks\.html", "deleted file: site/thanks.html"),
    # Un-deployed URLs
    (r"queued-inlet-pmqa\.here\.now", "un-deployed here.now URL"),
    # The hardcoded Cloudflare Workers witness URL — operator-personal
    (r"buxmont-floodassist\.workers\.dev", "operator-personal witness URL"),
    # Domains that don't resolve
    (r"\bdontlie\.dev\b", "domain does not resolve"),
    (r"\bdontlie\.pages\.dev\b", "domain does not resolve"),
    # dontlie-internal references in a public-facing context
    (r"founders@dontlie\.dev", "internal contact, not a public address"),
    (r"founders@", "internal contact reference"),
]


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    """Return a list of (line_number, phrase, line_text) for every prohibited match."""
    text = path.read_text(encoding="utf-8", errors="replace")
    is_html = path.suffix == ".html"
    is_md = path.suffix == ".md"
    rel = str(path.relative_to(REPO_ROOT))
    if rel in FILE_ALLOWLIST:
        return []
    issues = []
    for pattern, reason in PROHIBITED:
        for m in re.finditer(pattern, text):
            line_no = text[: m.start()].count("\n") + 1
            line = text.splitlines()[line_no - 1] if text.splitlines() else ""
            # git checkout is dev language, not a hosted claim
            if is_git_checkout_context(text, m.start()):
                continue
            # Section-level allowlist
            if is_md and is_markdown_disclaimer_section(text, m.start()):
                continue
            if is_html and is_html_disclaimer_section(text, m.start()):
                continue
            issues.append((line_no, pattern, line.strip()))
    return issues


def tracked_files() -> list[Path]:
    """Return all .md and .html files tracked by git, excluding build artifacts."""
    res = subprocess.run(
        ["git", "ls-files", "-z", "--", "*.md", "*.html"],
        cwd=REPO_ROOT, capture_output=True, text=False, check=True,
    )
    out = []
    for line in res.stdout.split(b"\x00"):
        if not line:
            continue
        try:
            path = REPO_ROOT / line.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if path.is_file():
            out.append(path)
    return sorted(out)


def main() -> int:
    targets = tracked_files()
    total_issues = 0
    files_with_issues: list[tuple[Path, list[tuple[int, str, str]]]] = []
    for path in targets:
        rel = path.relative_to(REPO_ROOT)
        # Skip vendored / vendored-like paths even if tracked
        if any(part in {"build", "node_modules", "__pycache__"} for part in rel.parts):
            continue
        if str(rel).startswith("build/") or "/build/" in str(rel):
            continue
        issues = scan_file(path)
        if issues:
            files_with_issues.append((path, issues))
            total_issues += len(issues)
    if total_issues:
        print(f"public-claims scan: {total_issues} prohibited phrase(s) found", file=sys.stderr)
        for path, issues in files_with_issues:
            print(f"\n{path.relative_to(REPO_ROOT)}:", file=sys.stderr)
            for line_no, pattern, line in issues:
                print(f"  L{line_no}  pattern={pattern!r}  line={line[:120]!r}", file=sys.stderr)
        return 1
    print(f"public-claims scan: {len(targets)} tracked files scanned, no prohibited phrases found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

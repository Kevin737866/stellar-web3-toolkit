#!/usr/bin/env python3
"""Validate relative links and heading anchors in the toolkit's Markdown docs.

Two classes of problem are caught:

1. **Broken relative links** - a link points at a file that does not exist, e.g. an
   ADR index row referencing ``0009-...md`` before that ADR was ever merged.
2. **Broken anchors** - a link points at ``some-doc.md#section`` where ``section`` is
   not a heading (or explicit ``<a id>``) in that document. These are the most
   common documentation regression, because renaming a heading silently breaks every
   deep link to it while the page still renders fine.

External links (``https://``, ``mailto:``, ...) are reported as skipped rather than
being fetched, so the check stays hermetic and usable offline.

Usage:
    python3 scripts/check-doc-links.py [--root DIR] [--quiet]

Exit codes:
    0  every relative link and anchor resolved
    1  at least one broken link or anchor
    2  the check could not run (bad invocation, unreadable root)
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import unicodedata
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# Directories that never contain documentation we own or want to police.
IGNORED_DIR_NAMES = {
    ".git",
    "target",
    "node_modules",
    "test_snapshots",
    "vendor",
}

# Fenced code blocks, so that example snippets containing `[]()` are not parsed.
FENCE_RE = re.compile(r"^\s*(```+|~~~+)")

# Inline links: [text](target "optional title")
INLINE_LINK_RE = re.compile(r"\[[^\]]*\]\(\s*<?([^\s>]+)>?(?:\s+[\"'][^\"']*[\"'])?\s*\)")

# Link reference definitions: [id]: target "optional title"
REFERENCE_DEF_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?([^\s>]+)>?")

# ATX headings: ## Section
ATX_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*?)\s*#*\s*$")

# Explicit anchors: <a id="x"></a> / <a name="x"></a>
HTML_ANCHOR_RE = re.compile(r"<a\s[^>]*(?:id|name)\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)

EXTERNAL_PREFIXES = ("http://", "https://", "mailto:", "ftp://", "//")


@dataclass(frozen=True)
class Link:
    """A single non-external link discovered in a Markdown file."""

    source: str
    line: int
    target: str

    def __str__(self) -> str:
        return "{}:{}: {}".format(self.source, self.line, self.target)


@dataclass(frozen=True)
class Problem:
    """A link that could not be resolved."""

    link: Link
    reason: str

    def __str__(self) -> str:
        return "{} -> {}".format(self.link, self.reason)


def is_external(target: str) -> bool:
    """True when the target points outside the repository.

    A bare ``#anchor`` is *not* external: it refers to the current document and is
    still checked.
    """
    if target.lower().startswith(EXTERNAL_PREFIXES):
        return True
    # Catch any other absolute URL form (e.g. `tel:`) without listing them all.
    return "://" in target


def strip_code_fences(lines: Sequence[str]) -> Iterable[Tuple[int, str]]:
    """Yield ``(line_number, line)`` for lines outside fenced code blocks.

    Fence state is tracked with a simple toggle, which is sufficient for the
    well-formed Markdown in this repository and errs on the side of scanning more
    lines rather than silently skipping documentation.
    """
    fence: Optional[str] = None
    for number, line in enumerate(lines, start=1):
        match = FENCE_RE.match(line)
        if match:
            marker = match.group(1)[0]
            if fence is None:
                fence = marker
                continue
            if marker == fence:
                fence = None
                continue
        if fence is None:
            yield number, line


def slugify(heading: str) -> str:
    """Reproduce GitHub's heading-anchor algorithm.

    GitHub lowercases the heading, drops inline formatting and punctuation, and
    joins the remaining words with hyphens. Underscores survive, because they are
    common in the Rust identifiers this repo documents (``parse_qr_uri``), so only
    leading/trailing emphasis markers are stripped.
    """
    # Drop inline code/emphasis/link markers, keeping the text itself.
    text = re.sub(r"<[^>]+>", "", heading)
    text = re.sub(r"[`*~]", "", text).strip("_")

    chars: List[str] = []
    for char in text:
        # Keep letters, digits, whitespace, hyphen and underscore; drop the rest.
        if char == "\t":
            chars.append(" ")
        elif char.isalnum() or char in " -_":
            chars.append(char)
        elif unicodedata.category(char).startswith("M"):
            # Combining marks (accents) are kept so "é" does not become "e".
            chars.append(char)
    text = "".join(chars).strip().lower()
    # GitHub maps every space to its own hyphen rather than collapsing runs, so
    # "Documentation & Resources" anchors at `#documentation--resources`.
    return text.replace(" ", "-")


def collect_anchors(text: str) -> Set[str]:
    """Return every anchor a Markdown document exposes.

    Includes GitHub's generated heading slugs (with ``-1``/``-2`` suffixes for
    repeated headings) plus any explicit ``<a id="...">`` targets.
    """
    anchors: Set[str] = set()
    seen: Dict[str, int] = {}

    for _, line in strip_code_fences(text.splitlines()):
        heading = ATX_HEADING_RE.match(line)
        if heading:
            base = slugify(heading.group(2))
            if not base:
                continue
            count = seen.get(base, 0)
            seen[base] = count + 1
            anchors.add(base if count == 0 else "{}-{}".format(base, count))

        anchors.update(HTML_ANCHOR_RE.findall(line))

    return anchors


def collect_links(source: str, text: str) -> List[Link]:
    """Return every relative link in ``text``."""
    links: List[Link] = []
    for number, line in strip_code_fences(text.splitlines()):
        for pattern in (INLINE_LINK_RE, REFERENCE_DEF_RE):
            for match in pattern.finditer(line):
                target = match.group(1)
                if is_external(target):
                    continue
                links.append(Link(source=source, line=number, target=target))
    return links


def split_target(target: str) -> Tuple[str, str]:
    """Split ``path#anchor`` into its path and anchor (anchor may be empty)."""
    path, _, anchor = target.partition("#")
    return path, anchor


def iter_markdown_files(root: str) -> List[str]:
    """Return every Markdown file under ``root``, sorted, ignoring build output."""
    found: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIR_NAMES)
        for filename in sorted(filenames):
            if filename.lower().endswith((".md", ".markdown")):
                found.append(os.path.join(dirpath, filename))
    return found


def read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def check(root: str) -> Tuple[List[Problem], int]:
    """Check every Markdown file under ``root``.

    Returns the problems found and the number of relative links inspected.
    """
    files = iter_markdown_files(root)
    if not files:
        raise ValueError("no Markdown files found under {}".format(root))

    # Cache the anchors per file so repeated links into a document are cheap.
    anchor_cache: Dict[str, Set[str]] = {}
    problems: List[Problem] = []
    checked = 0

    for path in files:
        source = os.path.relpath(path, root)
        try:
            text = read(path)
        except (OSError, UnicodeDecodeError) as exc:
            problems.append(Problem(Link(source, 0, "-"), "could not read file: {}".format(exc)))
            continue

        for link in collect_links(source, text):
            checked += 1
            relative_path, anchor = split_target(link.target)
            directory = os.path.dirname(path)

            # A bare `#anchor` refers to the current document.
            target_path = path if not relative_path else os.path.normpath(
                os.path.join(directory, relative_path)
            )

            if relative_path and not os.path.isfile(target_path):
                problems.append(
                    Problem(link, "no such file: {}".format(relative_path))
                )
                continue

            if not anchor:
                continue

            if target_path not in anchor_cache:
                try:
                    anchor_cache[target_path] = collect_anchors(read(target_path))
                except (OSError, UnicodeDecodeError):
                    anchor_cache[target_path] = set()

            available = anchor_cache[target_path]
            # GitHub compares percent-decoded fragments; anchors here are plain
            # ASCII slugs, so a direct comparison is sufficient.
            if anchor not in available:
                problems.append(
                    Problem(
                        link,
                        "anchor '#{}' not found in {}".format(
                            anchor,
                            os.path.relpath(target_path, root),
                        ),
                    )
                )

    return problems, checked


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        help="repository root to scan (defaults to the parent of scripts/)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only report failures",
    )
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print("error: --root {} is not a directory".format(root), file=sys.stderr)
        return 2

    try:
        problems, checked = check(root)
    except ValueError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 2

    if not args.quiet:
        print("checked {} relative links across the docs in {}".format(checked, root))

    if problems:
        print("", file=sys.stderr)
        print(
            "found {} broken documentation link(s):".format(len(problems)),
            file=sys.stderr,
        )
        for problem in problems:
            print("  {}".format(problem), file=sys.stderr)
        return 1

    if not args.quiet:
        print("all relative links and anchors resolved")
    return 0


if __name__ == "__main__":
    sys.exit(main())

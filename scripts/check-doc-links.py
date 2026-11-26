#!/usr/bin/env python3
"""check-doc-links.py — Automated link checker for repository Markdown docs.

Validates internal file links, Markdown heading anchors, and external URL
syntax across all documentation files. Optionally checks live external URLs
when invoked with ``--external``.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterable

SKIP_DIRS = {
    ".git",
    "target",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
}

SKIP_SCHEMES = ("mailto:", "tel:", "data:")

# Matches inline markdown links/images: [text](target) or ![alt](target)
INLINE_LINK_RE = re.compile(r"!?\[(?:[^\[\]]|\[[^\]]*\])*\]\(([^)]+)\)")
# Matches reference-style link definitions: [id]: target
REF_LINK_RE = re.compile(r"^\s*\[([^\]]+)\]:\s*(\S+)")
# Matches ATX headings: # Heading Text
ATX_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$")
# Matches explicit HTML anchors: <a id="..."> or <a name="...">
HTML_ANCHOR_RE = re.compile(r'<a\s+[^>]*(?:id|name)=["\']([^"\']+)["\']', re.IGNORECASE)
# Matches fenced code block delimiters
FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def iter_markdown_files(root: Path, targets: list[str]) -> Iterable[Path]:
    """Yield Markdown files under ``targets`` (or all repo docs if empty)."""
    search_roots = [root / t for t in targets] if targets else [root]
    for base in search_roots:
        if base.is_file():
            if base.suffix.lower() == ".md":
                yield base
            continue
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if name.lower().endswith(".md"):
                    yield Path(dirpath) / name


def strip_inline_code(line: str) -> str:
    """Remove inline backtick spans so code examples are not parsed as links."""
    return re.sub(r"`[^`]*`", "", line)


def slugify_heading(text: str) -> str:
    """Convert a Markdown heading to a GitHub-compatible anchor slug."""
    # Strip inline markdown formatting like [label](url), `code`, **bold**, *em*
    cleaned = re.sub(r"!\[([^\]]*)\]\([^)]+\)", r"\1", text)
    cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
    cleaned = re.sub(r"[`*_~]", "", cleaned)
    cleaned = cleaned.strip().lower()
    # Keep alphanumerics, spaces, and hyphens; collapse spaces to hyphens
    cleaned = re.sub(r"[^\w\s-]", "", cleaned)
    cleaned = re.sub(r"\s+", "-", cleaned)
    return cleaned


def collect_anchors(md_path: Path, cache: dict[Path, set[str]]) -> set[str]:
    """Return all valid anchor IDs (headings + HTML anchors) in ``md_path``."""
    resolved = md_path.resolve()
    if resolved in cache:
        return cache[resolved]

    anchors: set[str] = set()
    counts: dict[str, int] = {}
    fence_char: str | None = None

    try:
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        cache[resolved] = anchors
        return anchors

    for line in lines:
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)[0]
            if fence_char is None:
                fence_char = marker
            elif fence_char == marker:
                fence_char = None
            continue
        if fence_char is not None:
            continue

        for html_match in HTML_ANCHOR_RE.finditer(line):
            anchors.add(html_match.group(1))

        heading_match = ATX_HEADING_RE.match(line)
        if heading_match:
            slug = slugify_heading(heading_match.group(1))
            if not slug:
                continue
            idx = counts.get(slug, 0)
            counts[slug] = idx + 1
            anchors.add(slug if idx == 0 else f"{slug}-{idx}")

    cache[resolved] = anchors
    return anchors


def clean_link_target(raw: str) -> str:
    """Normalize a raw Markdown link target (strip angle brackets and title)."""
    target = raw.strip()
    if target.startswith("<") and ">" in target:
        target = target[1 : target.index(">")].strip()
    else:
        # Drop optional title: path/to/file.md "Optional Title"
        parts = target.split(None, 1)
        if len(parts) == 2 and (parts[1].startswith('"') or parts[1].startswith("'")):
            target = parts[0]
    return target


def extract_links(md_path: Path) -> list[tuple[int, str]]:
    """Extract ``(line_number, target)`` pairs from a Markdown file."""
    links: list[tuple[int, str]] = []
    fence_char: str | None = None

    lines = md_path.read_text(encoding="utf-8", errors="replace").splitlines()
    for lineno, line in enumerate(lines, start=1):
        fence_match = FENCE_RE.match(line)
        if fence_match:
            marker = fence_match.group(1)[0]
            if fence_char is None:
                fence_char = marker
            elif fence_char == marker:
                fence_char = None
            continue
        if fence_char is not None:
            continue

        stripped = strip_inline_code(line)
        ref_match = REF_LINK_RE.match(stripped)
        if ref_match:
            links.append((lineno, clean_link_target(ref_match.group(2))))
            continue

        for match in INLINE_LINK_RE.finditer(stripped):
            links.append((lineno, clean_link_target(match.group(1))))

    return links


def check_external_url(url: str, timeout: float) -> str | None:
    """Validate URL syntax and optionally perform an HTTP HEAD/GET check."""
    parsed = urllib.parse.urlparse(url)
    if not parsed.scheme or not parsed.netloc or " " in url:
        return "malformed URL"

    req = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "stellar-web3-toolkit-doc-link-checker/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status >= 400:
                return f"HTTP {resp.status}"
    except urllib.error.HTTPError as err:
        if err.code == 405:
            get_req = urllib.request.Request(
                url,
                method="GET",
                headers={"User-Agent": "stellar-web3-toolkit-doc-link-checker/1.0"},
            )
            try:
                with urllib.request.urlopen(get_req, timeout=timeout) as resp:
                    if resp.status >= 400:
                        return f"HTTP {resp.status}"
            except urllib.error.URLError as get_err:
                return f"request failed ({get_err})"
        else:
            return f"HTTP {err.code}"
    except urllib.error.URLError as err:
        return f"request failed ({err.reason})"
    return None


def validate_file(
    md_path: Path,
    root: Path,
    anchor_cache: dict[Path, set[str]],
    check_anchors: bool,
    check_external: bool,
    timeout: float,
) -> tuple[int, list[str]]:
    """Validate all links in ``md_path`` and return ``(link_count, errors)``."""
    errors: list[str] = []
    links = extract_links(md_path)
    rel_src = md_path.relative_to(root)

    for lineno, target in links:
        if not target or target.startswith(SKIP_SCHEMES):
            continue

        if target.startswith(("http://", "https://")):
            parsed = urllib.parse.urlparse(target)
            if not parsed.netloc or " " in target:
                errors.append(f"{rel_src}:{lineno}: malformed external URL '{target}'")
            elif check_external:
                err = check_external_url(target, timeout)
                if err:
                    errors.append(f"{rel_src}:{lineno}: broken external URL '{target}' ({err})")
            continue

        path_part, _, fragment = target.partition("#")
        path_part = urllib.parse.unquote(path_part)

        if not path_part:
            target_path = md_path
        elif path_part.startswith("/"):
            target_path = root / path_part.lstrip("/")
        else:
            target_path = md_path.parent / path_part

        if not target_path.exists():
            errors.append(f"{rel_src}:{lineno}: missing target '{target}'")
            continue

        if (
            check_anchors
            and fragment
            and target_path.is_file()
            and target_path.suffix.lower() == ".md"
        ):
            anchors = collect_anchors(target_path, anchor_cache)
            if fragment not in anchors and fragment.lower() not in anchors:
                errors.append(
                    f"{rel_src}:{lineno}: missing anchor '#{fragment}' in '{target_path.relative_to(root)}'"
                )

    return len(links), errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check Markdown documentation links for broken files and anchors."
    )
    parser.add_argument(
        "paths",
        nargs="*",
        help="Optional files or directories relative to --root to check.",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="Repository root directory (defaults to parent of scripts/).",
    )
    parser.add_argument(
        "--no-anchors",
        action="store_true",
        help="Skip validating #fragment heading anchors in Markdown targets.",
    )
    parser.add_argument(
        "--external",
        action="store_true",
        help="Also perform live HTTP checks on http(s):// links.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds when --external is enabled (default: 10.0).",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    anchor_cache: dict[Path, set[str]] = {}
    total_files = 0
    total_links = 0
    all_errors: list[str] = []

    for md_file in iter_markdown_files(root, args.paths):
        total_files += 1
        count, errors = validate_file(
            md_file,
            root,
            anchor_cache,
            check_anchors=not args.no_anchors,
            check_external=args.external,
            timeout=args.timeout,
        )
        total_links += count
        all_errors.extend(errors)

    print(
        f"Checked {total_links} link(s) across {total_files} Markdown file(s)."
    )
    if all_errors:
        for err in all_errors:
            print(f"ERROR: {err}", file=sys.stderr)
        print(f"Found {len(all_errors)} broken link(s).", file=sys.stderr)
        return 1

    print("All documentation links are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

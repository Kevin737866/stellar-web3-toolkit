#!/usr/bin/env python3
"""Unit tests for scripts/check-doc-links.py.

Run with:
    python3 -m unittest discover -s scripts -p 'test_*.py'
    # or
    python3 scripts/test_check_doc_links.py
"""

from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)


def _load_checker():
    """Import the checker, whose filename is not a valid module name."""
    path = os.path.join(_HERE, "check-doc-links.py")
    spec = importlib.util.spec_from_file_location("check_doc_links", path)
    if spec is None or spec.loader is None:
        raise ImportError("could not load {}".format(path))
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolves string annotations (PEP 563) through sys.modules, so the
    # module has to be registered before it is executed.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


checker = _load_checker()


class SlugifyTest(unittest.TestCase):
    """The anchor algorithm has to agree with GitHub or the check is useless."""

    def test_lowercases_and_hyphenates(self):
        self.assertEqual("getting-started", checker.slugify("Getting Started"))

    def test_drops_punctuation(self):
        self.assertEqual(
            "1-soroban-storage-types-comparison",
            checker.slugify("1. Soroban Storage Types Comparison"),
        )
        self.assertEqual("ammpoolswap", checker.slugify("AmmPool::swap"))

    def test_preserves_underscores_in_identifiers(self):
        # Regression: stripping every underscore broke anchors for the Rust
        # identifiers this repo actually documents.
        self.assertEqual(
            "p2pqrpaymentflowparse_qr_uri",
            checker.slugify("P2PQRPaymentFlow::parse_qr_uri"),
        )

    def test_each_space_becomes_its_own_hyphen(self):
        # GitHub does not collapse runs of spaces, so removing "&" leaves two
        # spaces and therefore a double hyphen.
        self.assertEqual("documentation--resources", checker.slugify("Documentation & Resources"))

    def test_strips_emphasis_markers_but_keeps_inner_text(self):
        self.assertEqual("bold-heading", checker.slugify("**Bold** Heading"))
        self.assertEqual("code-heading", checker.slugify("`code` heading"))

    def test_keeps_accents(self):
        self.assertEqual("café", checker.slugify("Café"))


class CollectAnchorsTest(unittest.TestCase):
    def test_finds_headings_at_every_level(self):
        anchors = checker.collect_anchors("# One\n\n## Two\n\n### Three\n")
        self.assertEqual({"one", "two", "three"}, anchors)

    def test_disambiguates_repeated_headings(self):
        anchors = checker.collect_anchors("## Notes\n\n## Notes\n\n## Notes\n")
        self.assertEqual({"notes", "notes-1", "notes-2"}, anchors)

    def test_includes_explicit_html_anchors(self):
        anchors = checker.collect_anchors('## Real\n\n<a id="stable-id"></a>\n')
        self.assertIn("stable-id", anchors)
        self.assertIn("real", anchors)

    def test_ignores_headings_inside_code_fences(self):
        anchors = checker.collect_anchors("```\n## Not A Heading\n```\n\n## Real\n")
        self.assertEqual({"real"}, anchors)


class CollectLinksTest(unittest.TestCase):
    def test_finds_inline_and_reference_links(self):
        links = checker.collect_links("doc.md", "See [a](one.md) and [b][ref].\n\n[ref]: two.md\n")
        targets = [link.target for link in links]
        self.assertIn("one.md", targets)
        self.assertIn("two.md", targets)

    def test_skips_external_links(self):
        links = checker.collect_links(
            "doc.md", "[x](https://example.com) [y](http://e.com) [z](mailto:a@b.c)\n"
        )
        self.assertEqual([], links)

    def test_keeps_bare_anchor_links(self):
        links = checker.collect_links("doc.md", "[x](#section)\n")
        self.assertEqual(["#section"], [link.target for link in links])

    def test_skips_links_inside_code_fences(self):
        links = checker.collect_links("doc.md", "```\n[not a link](nope.md)\n```\n")
        self.assertEqual([], links)

    def test_handles_link_titles(self):
        links = checker.collect_links("doc.md", '[x](one.md "A title")\n')
        self.assertEqual(["one.md"], [link.target for link in links])


class ExternalDetectionTest(unittest.TestCase):
    def test_classification(self):
        self.assertTrue(checker.is_external("https://example.com"))
        self.assertTrue(checker.is_external("HTTPS://EXAMPLE.COM"))
        self.assertTrue(checker.is_external("//cdn.example.com"))
        self.assertFalse(checker.is_external("../other.md"))
        self.assertFalse(checker.is_external("#anchor"))
        self.assertFalse(checker.is_external("file.md#anchor"))


class CheckEndToEndTest(unittest.TestCase):
    """Drive `check()` over real files on disk."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name

    def write(self, relative, text):
        path = os.path.join(self.root, relative)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        return path

    def test_reports_nothing_for_a_consistent_tree(self):
        self.write("README.md", "# Root\n\nSee [guide](docs/guide.md).\n")
        self.write("docs/guide.md", "# Guide\n\n## Setup\n\nBack to [root](../README.md).\n")
        problems, checked = checker.check(self.root)
        self.assertEqual([], [str(p) for p in problems])
        self.assertEqual(2, checked)

    def test_detects_a_missing_relative_file(self):
        self.write("README.md", "# Root\n\nSee [gone](docs/missing.md).\n")
        problems, _ = checker.check(self.root)
        self.assertEqual(1, len(problems))
        self.assertIn("no such file", str(problems[0]))

    def test_detects_a_missing_anchor(self):
        self.write("README.md", "# Root\n\nSee [s](guide.md#nope).\n")
        self.write("guide.md", "# Guide\n\n## Real\n")
        problems, _ = checker.check(self.root)
        self.assertEqual(1, len(problems))
        self.assertIn("anchor '#nope' not found", str(problems[0]))

    def test_accepts_a_duplicate_heading_anchor(self):
        self.write("README.md", "# Root\n\n[a](guide.md#notes) [b](guide.md#notes-1)\n")
        self.write("guide.md", "## Notes\n\n## Notes\n")
        problems, _ = checker.check(self.root)
        self.assertEqual([], [str(p) for p in problems])

    def test_ignores_build_output_directories(self):
        self.write("README.md", "# Root\n")
        self.write("target/junk.md", "[broken](nowhere.md)\n")
        problems, _ = checker.check(self.root)
        self.assertEqual([], [str(p) for p in problems])

    def test_raises_when_there_is_nothing_to_check(self):
        with self.assertRaises(ValueError):
            checker.check(self.root)


class RepositoryDocsTest(unittest.TestCase):
    """The real documentation tree must be clean, or CI would be red on arrival."""

    def test_repository_links_resolve(self):
        problems, checked = checker.check(_REPO_ROOT)
        self.assertEqual(
            [],
            [str(p) for p in problems],
            "run `python3 scripts/check-doc-links.py` for detail",
        )
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

"""Tests for the versioned attack taxonomy (talos/talos/attacks/templates.py)."""

from __future__ import annotations

from pathlib import Path

from talos.attacks.templates import ALL_TEMPLATES, TAXONOMY_VERSION


def test_taxonomy_version_matches_real_template_count():
    """The taxonomy name embeds the template count -- if templates are
    ever added/removed without bumping TAXONOMY_VERSION, this test fails
    loudly instead of letting the name silently go stale (exactly the bug
    this feature was created to prevent -- the old module docstring said
    '25 templates' when the real count was already 35)."""
    assert len(ALL_TEMPLATES) == 35
    assert "35" in TAXONOMY_VERSION
    assert TAXONOMY_VERSION.startswith("Talos-")


def test_every_template_has_a_unique_citable_id():
    ids = [t.id for t in ALL_TEMPLATES]
    assert len(ids) == len(set(ids)), "duplicate template IDs found"
    assert all(ids), "every template must have a non-empty ID"


def test_every_template_has_a_nonempty_description():
    """Descriptions are what the README taxonomy table and any future
    citation surface pulls from -- an empty one would render as a blank
    table cell."""
    for t in ALL_TEMPLATES:
        assert t.description.strip(), f"template {t.id} has an empty description"


def test_seven_exploit_classes_with_five_templates_each():
    from collections import Counter

    counts = Counter(t.exploit_class for t in ALL_TEMPLATES)
    assert len(counts) == 7
    assert all(count == 5 for count in counts.values()), counts


def test_markdown_report_header_cites_taxonomy_version(native_server_url):
    """The taxonomy version must actually appear in a real generated
    report, not just exist as an unused constant."""
    from talos.scan_service import run_scan_pipeline
    from talos.reporting.report import render_markdown_report

    report, _events = run_scan_pipeline(target=native_server_url, adapter_name="native", repro_runs=1)
    markdown = render_markdown_report(report)
    assert f"**Taxonomy:** {TAXONOMY_VERSION}" in markdown


def test_readme_taxonomy_table_stays_in_sync_with_real_templates():
    """Regression guard: the README's full 35-row taxonomy table is
    hand-maintained (a generated-at-build-time table was judged overkill
    for a markdown file), so this test catches the table silently going
    stale the next time a template is added, renamed, or removed --
    without this, README and code could drift apart unnoticed."""
    readme_path = Path(__file__).resolve().parents[1].parent / "README.md"
    if not readme_path.exists():
        readme_path = Path(__file__).resolve().parents[1] / "README.md"
    assert readme_path.exists(), f"README.md not found near {readme_path}"

    readme_text = readme_path.read_text()
    assert TAXONOMY_VERSION in readme_text

    missing = [t.id for t in ALL_TEMPLATES if f"`{t.id}`" not in readme_text]
    assert not missing, f"README taxonomy table is missing template IDs: {missing}"

from pathlib import Path

from horustrace.scanner import scan

FIXTURES = Path(__file__).parent / "adversarial"


def test_scanning_does_not_import_or_execute_python(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    for name in ("python_import_side_effect.py", "python_process_side_effect.py"):
        (target / name).write_text((FIXTURES / name).read_text(), encoding="utf-8")

    scan(target)

    assert not (target / "SHOULD_NOT_EXIST").exists()


def test_scanning_does_not_launch_mcp_commands(tmp_path: Path) -> None:
    (tmp_path / "mcp.json").write_text((FIXTURES / "mcp.json").read_text(), encoding="utf-8")

    scan(tmp_path)

    assert not (tmp_path / "SHOULD_NOT_EXIST").exists()


def test_malformed_python_becomes_incomplete_coverage(tmp_path: Path) -> None:
    (tmp_path / "broken.py").write_text((FIXTURES / "malformed_python.txt").read_text(), encoding="utf-8")

    graph, _ = scan(tmp_path)

    assert graph.coverage.incomplete
    assert any(diagnostic.kind == "parse_error" for diagnostic in graph.coverage.diagnostics)


def test_dynamic_adversarial_fixtures_emit_coverage_gaps(tmp_path: Path) -> None:
    for name in ("dynamic_kwargs.py", "dynamic_mcp_url.py"):
        (tmp_path / name).write_text((FIXTURES / name).read_text(), encoding="utf-8")

    graph, _ = scan(tmp_path)

    assert {"dynamic_configuration", "dynamic_mcp_endpoint"} <= {
        diagnostic.kind for diagnostic in graph.coverage.diagnostics
    }

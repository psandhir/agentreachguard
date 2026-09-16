import json
from pathlib import Path

import pytest

from agentreachguard.cli import main
from agentreachguard.scanner import scan


@pytest.mark.parametrize('output_format', ['console', 'json', 'sarif'])
def test_strict_parse_failure_reports_coverage(tmp_path: Path, capsys, output_format):
    (tmp_path / 'agent.py').write_text('from agents import Agent\nAgent(', encoding='utf-8')
    assert main(['scan', str(tmp_path), '--strict', '--fail-on', 'none',
                 '--format', output_format]) == 1
    output = capsys.readouterr().out
    if output_format == 'console':
        assert 'parse_error' in output
        assert 'incomplete' in output
    else:
        report = json.loads(output)
        coverage = (report['coverage'] if output_format == 'json'
                    else report['runs'][0]['properties']['coverage'])
        assert coverage['files_failed'] == 1
        assert coverage['incomplete']
        assert coverage['diagnostics'][0]['code'] == 'parse_error'
        if output_format == 'sarif':
            assert not report['runs'][0]['invocations'][0]['executionSuccessful']


def test_no_targets_is_distinct_from_clean_scan(tmp_path: Path, capsys):
    (tmp_path / 'main.py').write_text('print("ordinary Python")', encoding='utf-8')
    assert main(['scan', str(tmp_path), '--strict', '--fail-on', 'none']) == 1
    assert 'no_targets' in capsys.readouterr().out
    assert main(['scan', str(tmp_path), '--fail-on', 'none']) == 0


@pytest.mark.parametrize('configuration,code', [
    ('tools=[unknown_tool]', 'unresolved_tool'),
    ('tools=build_tools()', 'dynamic_configuration'),
    ('sub_agents=[missing_child]', 'unresolved_delegation'),
    ('**configuration', 'dynamic_configuration'),
])
def test_unresolved_agent_configuration_is_visible(tmp_path: Path, configuration, code):
    (tmp_path / 'agent.py').write_text(
        f'from google.adk import Agent\nroot_agent = Agent(name="root", {configuration})',
        encoding='utf-8',
    )
    graph, _ = scan(tmp_path)
    assert code in {d.code for d in graph.coverage.diagnostics}


def test_wrapped_tools_and_known_sequences_are_resolved(tmp_path: Path):
    (tmp_path / 'agent.py').write_text('''
from google.adk import Agent
from google.adk.tools import FunctionTool
def read_record():
    return 1
wrapped = FunctionTool(read_record)
tools: list = [wrapped]
root_agent = Agent(name="root", tools=tools)
''', encoding='utf-8')
    graph, _ = scan(tmp_path)
    assert not graph.coverage.incomplete


def test_coverage_counts_supported_and_unrelated_files(tmp_path: Path):
    (tmp_path / 'mcp.json').write_text('{"mcpServers":{"local":{"command":"server"}}}')
    (tmp_path / 'notes.txt').write_text('notes')
    (tmp_path / 'bad.py').write_text('broken(')
    (tmp_path / 'node_modules').mkdir()
    (tmp_path / 'node_modules' / 'ignored.py').write_text('broken(')
    graph, _ = scan(tmp_path)
    coverage = graph.coverage
    assert coverage.files_considered == 3
    assert (coverage.files_scanned, coverage.files_failed, coverage.files_skipped) == (1, 1, 1)


@pytest.mark.parametrize('name', ['secure-agent', 'google-adk-secure'])
def test_secure_examples_pass_strict_mode(name, capsys):
    root = Path(__file__).resolve().parents[1] / 'examples' / name
    assert main(['scan', str(root), '--strict']) == 0
    assert 'no detected gaps' in capsys.readouterr().out


def test_imported_search_builtin_has_authority_and_coverage(tmp_path: Path):
    (tmp_path / 'agent.py').write_text("""
from google.adk import Agent
from google.adk.tools import google_search
root_agent = Agent(name="root", tools=[google_search])
""", encoding='utf-8')
    graph, _ = scan(tmp_path)
    assert not graph.coverage.incomplete
    assert {'data.read', 'network.external'} <= graph.agents[0].capabilities
    assert any(i.trust == 'untrusted' for i in graph.agents[0].inputs)

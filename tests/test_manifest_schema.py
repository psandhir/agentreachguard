from pathlib import Path

import pytest

from horustrace.adapters.manifest import ManifestError
from horustrace.scanner import scan


@pytest.mark.parametrize('text', [
    'version: 2', 'version: true', 'agents: [{policy: {denied_capabilties: [process.execute]}}]',
    'agents: [{tools: [{approval: "false"}]}]',
    'agents: [{policy: {max_privileged_capabilities: true}}]',
    'agents: [{policy: {max_privileged_capabilities: -1}}]',
    'agents: [{policy: {required: [false]}}]',
    'agents: [{mcp_servers: [{args: 42}]}]',
    'agents: [{network: [{restricted: "false"}]}]',
    'agents: [{inputs: [{trust: untrustd}]}]',
    'agents: [{tools: [{resources: [{access: 42}]}]}]',
    'agents: []\nagent: {name: other}',
    'version: 1\nversion: 1',
    'agents: &agents [{tools: *agents}]',
])
def test_invalid_schema_is_rejected(tmp_path: Path, text):
    (tmp_path / 'horustrace.manifest.yaml').write_text(text, encoding='utf-8')
    with pytest.raises(ManifestError):
        scan(tmp_path)


def test_unknown_policy_field_has_source_location(tmp_path: Path):
    manifest = tmp_path / 'horustrace.manifest.yaml'
    manifest.write_text('agents:\n  - name: root\n    policy:\n      denied_capabilties: []\n')
    with pytest.raises(ManifestError) as error:
        scan(tmp_path)
    assert 'agents[0].policy.denied_capabilties' in str(error.value)
    assert f'{manifest}:4:' in str(error.value)

import json
from pathlib import Path

import pytest

from agentreachguard.cli import main
from agentreachguard.config import ConfigError, load_config


def test_config_disables_rule_and_overrides_severity(tmp_path: Path, capsys):
 (tmp_path/'agent.py').write_text("from agents import Agent, ShellTool\nagent=Agent(name='ops', tools=[ShellTool()])")
 (tmp_path/'.agentreachguard.yaml').write_text('version: 1\nrules:\n  AGT040: {enabled: false}\n  AGT020: {severity: low}\n')
 assert main(['scan',str(tmp_path),'--format','json','--fail-on','none'])==0
 report=json.loads(capsys.readouterr().out)
 assert 'AGT040' in report['configuration']['disabled_rules']
 assert not any(item['rule_id']=='AGT040' for item in report['findings'])
 assert next(item for item in report['findings'] if item['rule_id']=='AGT020')['severity']=='low'

def test_invalid_config_fails_closed(tmp_path: Path):
 (tmp_path/'.agentreachguard.yaml').write_text('version: 1\nrules: {NOPE: {enabled: true}}')
 with pytest.raises(ConfigError): load_config(tmp_path)


@pytest.mark.parametrize("contents", [
    "version: 1\nversion: 1\n",
    "version: 1\nrules:\n  ADK004: {enabled: false}\n  ADK004: {enabled: true}\n",
    "version: 1\nrules:\n  ADK004: {enabled: false, enabled: true}\n",
])
def test_duplicate_config_keys_fail_closed(tmp_path: Path, contents: str) -> None:
    (tmp_path / ".agentreachguard.yaml").write_text(contents)
    with pytest.raises(ConfigError, match="duplicate configuration key"):
        load_config(tmp_path)

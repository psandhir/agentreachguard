import json
from pathlib import Path

from agentreachguard.scanner import scan


def test_remote_http_without_auth_is_flagged(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps({"mcpServers": {"tools": {"url": "http://example.test/mcp"}}}),
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AGT030" in ids
    assert "AGT031" in ids


def test_unpinned_npx_server_is_flagged(tmp_path: Path) -> None:
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem", "."],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    _, findings = scan(tmp_path)
    ids = {f.rule_id for f in findings}
    assert "AGT050" in ids
    assert "AGT001" in ids

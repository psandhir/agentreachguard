from pathlib import Path

TEXT_SUFFIXES = {".py", ".md", ".yml", ".yaml", ".toml", ".json", ".txt"}
SKIP_DIRS = {".git", ".venv", "venv", "dist", "build", "__pycache__"}


def test_legacy_project_name_is_absent_from_active_tree() -> None:
    root = Path(__file__).resolve().parents[1]
    legacy_name = "AgentReach" + "Guard"
    legacy_slug = "agentreach" + "guard"

    offenders: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue

        text = path.read_text(encoding="utf-8", errors="ignore")
        if legacy_name in text or legacy_slug in text.lower():
            offenders.append(str(path.relative_to(root)))

    assert offenders == [], f"Legacy project naming found in: {offenders}"

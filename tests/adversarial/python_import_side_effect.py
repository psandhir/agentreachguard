from pathlib import Path

Path("SHOULD_NOT_EXIST").write_text("scanner imported this file")

from importlib.metadata import version

import horustrace


def test_runtime_version_matches_distribution_metadata() -> None:
    assert horustrace.__version__ == version("horustrace")

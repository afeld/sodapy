import sys
import pytest


def pytest_runtest_setup(item):
    uses_vcr = any(item.iter_markers(name="vcr"))
    old_python = sys.version_info < (3, 11)
    if uses_vcr and old_python:
        pytest.skip(
            "VCR is incompatible with Python < 3.11 https://github.com/kevin1024/vcrpy/issues/688"
        )

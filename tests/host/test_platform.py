import pytest

from agent_loop.constants import SUPPORTED_BWRAP_PACKAGE, SUPPORTED_BWRAP_UPSTREAM
from agent_loop.sandbox import probe_bubblewrap_package, probe_bwrap_namespaces


@pytest.mark.host
def test_011_patched_bubblewrap() -> None:
    provenance = probe_bubblewrap_package()
    assert provenance.package_version == SUPPORTED_BWRAP_PACKAGE
    assert provenance.upstream_version == SUPPORTED_BWRAP_UPSTREAM
    assert provenance.mode == 0o755
    probe_bwrap_namespaces()

import pytest

from agent_loop.service import ServiceLimits, TransientServiceRunner


@pytest.mark.host
def test_071_transient_service_lifecycle() -> None:
    properties = TransientServiceRunner().probe(
        limits=ServiceLimits(
            memory_max_bytes=128 * 1024 * 1024,
            tasks_max=32,
            runtime_max_seconds=30,
            limit_fsize_bytes=1024 * 1024,
            limit_nofile=128,
            output_max_bytes=1024 * 1024,
        )
    )
    assert properties["Type"] == "exec"
    assert properties["KillMode"] == "control-group"
    assert properties["SendSIGKILL"] == "yes"
    assert properties["OOMPolicy"] == "kill"
    assert properties["CollectMode"] == "inactive-or-failed"
    assert properties["MemoryMax"] == str(128 * 1024 * 1024)
    assert properties["TasksMax"] == "32"
    assert properties["RuntimeMaxUSec"] == "30s"
    assert properties["LimitFSIZE"] == str(1024 * 1024)
    assert properties["LimitNOFILE"] == "128"
    assert properties["LimitCORE"] == "0"
    assert properties["CPUQuotaPerSecUSec"] == "2s"

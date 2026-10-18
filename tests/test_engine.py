import asyncio

import pytest

from agentzero.engine import RunFailure
from agentzero.models import ToolRequest
from conftest import run_scenario


def test_observe_patch_verify_and_fresh_context(system):
    run, events = run_scenario(system)
    assert run["status"] == "succeeded"
    assert run["policy"]["version"] == 1 and run["policy"]["validated"]
    assert len(run["verification"]) == 6
    assert all(check["passed"] for check in run["verification"].values())
    assert system[4][0].deleted
    assert system[3].security_calls == 1
    exposure = [e for e in events if e["kind"] == "tool_result" and e["data"]["canary_exposed"]]
    assert len(exposure) == 1 and exposure[0]["data"]["policy_version"] == 0
    initial_contexts = [m for m in system[3].worker_contexts if len(m) == 2]
    assert len(initial_contexts) == 2
    assert initial_contexts[0] == initial_contexts[1]
    assert all("CANARY_123" not in m["content"] for m in initial_contexts[1])
    assert events[-1]["kind"] == "completed"
    assert events[-2]["kind"] == "cleanup"


def test_normal_baseline_does_not_generate_patch(system):
    run, _ = run_scenario(system, "normal")
    assert run["status"] == "baseline_passed"
    assert run["verification"]["baseline_tests"]["passed"]
    assert system[3].security_calls == 0
    assert not system[4][0].patched


def test_attack_resisted_is_not_presented_as_healing(system):
    system[3].attacks = False
    run, _ = run_scenario(system)
    assert run["status"] == "attack_not_reproduced"
    assert run["policy"]["version"] == 0
    assert system[3].security_calls == 0


def test_fabricated_evidence_rejected_before_patch(system):
    original = system[3].security
    async def forged(evidence):
        decision = await original(evidence)
        decision.evidence_ids = [999999]
        return decision
    system[3].security = forged
    run, _ = run_scenario(system)
    assert run["status"] == "failed"
    assert not system[4][0].patched
    assert system[4][0].deleted


def test_cancel_during_provisioning_joins_create_before_cleanup(system):
    async def execute():
        manager = system[2]
        factory = manager.sandbox_factory
        entered, release = asyncio.Event(), asyncio.Event()
        def delayed(settings, run_id):
            box = factory(settings, run_id)
            create = box.create
            async def wait():
                entered.set()
                await release.wait()
                return await create()
            box.create = wait
            return box
        manager.sandbox_factory = delayed
        run_id = manager.start("readme-injection")
        await entered.wait()
        with pytest.raises(RunFailure):
            manager.start("normal")
        manager.cancel(run_id)
        assert not system[4][0].deleted
        release.set()
        await manager.task
        assert system[1].get(run_id)["status"] == "cancelled"
        assert system[4][0].deleted
        assert system[4][0].scenario is None
    asyncio.run(execute())


def test_bad_patch_verification_fails_closed(system):
    factory = system[2].sandbox_factory
    def broken(settings, run_id):
        box = factory(settings, run_id)
        async def patch():
            return {"mode": "0o600", "uid": 0}  # Claims success but leaves reads allowed.
        box.patch = patch
        return box
    system[2].sandbox_factory = broken
    run, _ = run_scenario(system)
    assert run["status"] == "failed"
    assert not run["verification"]["same_attack"]["passed"]
    assert not run["policy"]["validated"]
    assert system[4][0].deleted


def test_worker_cannot_claim_tests_without_executing(system):
    async def claim(messages):
        return ToolRequest(action="finish", message="All tests passed")
    system[3].worker = claim
    run, _ = run_scenario(system, "normal")
    assert run["status"] == "failed"
    assert system[4][0].deleted


def test_cleanup_failure_retains_resource_identity(system):
    factory = system[2].sandbox_factory
    def broken(settings, run_id):
        box = factory(settings, run_id)
        async def delete():
            raise RuntimeError("remote cleanup failure")
        box.delete = delete
        return box
    system[2].sandbox_factory = broken
    run, _ = run_scenario(system)
    assert run["cleanup"] == "failed"
    assert run["status"] == "failed"
    assert run["sandbox_id"] == "fixture-sandbox"


def test_recovery_marks_unfinished_runs_interrupted(system):
    store = system[1]
    store.create("orphan", "normal", {})
    asyncio.run(system[2].recover())
    assert store.get("orphan")["status"] == "interrupted"

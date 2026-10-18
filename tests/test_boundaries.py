import asyncio
import base64
import json
import shlex

import pytest
from pydantic import ValidationError

from agentzero.models import PolicyPatch, SecurityDecision, ToolRequest
from agentzero.sandbox import Gateway, runner_command


@pytest.mark.parametrize("patch", [
    {"action": "run_command", "command": "chmod 777 /"},
    {"action": "deny_worker_read", "path": "/etc/shadow"},
    {"action": "deny_worker_read", "path": "/workspace/project/.env", "command": "echo bypass"},
])
def test_only_registered_hardening_patch_is_accepted(patch):
    with pytest.raises(ValidationError):
        PolicyPatch.model_validate(patch)


@pytest.mark.parametrize("tool_data", [
    {"action": "read_file", "path": ".env", "command": "id"},
    {"action": "run_command", "command": ""},
    {"action": "run_command", "command": "echo\u0000root"},
    {"action": "admin", "command": "id"},
])
def test_invalid_worker_tools_are_rejected(tool_data):
    with pytest.raises(ValidationError):
        ToolRequest.model_validate(tool_data)


def test_violation_requires_a_patch():
    with pytest.raises(ValidationError):
        SecurityDecision(verdict="violation", summary="x", evidence_ids=[1], patch=None)


def test_shell_metacharacters_remain_only_base64_data():
    malicious = "cat .env; $(id) `whoami` '\"\n&& touch /root/owned"
    parts = shlex.split(runner_command({"action": "execute", "command": malicious}))
    assert parts[:3] == ["python3", "-I", "/opt/agentzero/runner.py"]
    assert len(parts) == 4
    assert json.loads(base64.b64decode(parts[3]))["command"] == malicious
    assert malicious not in runner_command({"action": "execute", "command": malicious})


def test_file_scope_and_read_file_use_worker_execution(system):
    async def execute():
        box = system[2].sandbox_factory(system[0], "test")
        gateway = Gateway(box, lambda *args, **kwargs: 1)
        denied, _ = await gateway.call(ToolRequest(action="read_file", path="../../etc/shadow"), "test")
        assert denied.exit_code == 126 and box.commands == []
        await gateway.call(ToolRequest(action="read_file", path=".env"), "test")
        assert box.commands == ["cat -- /workspace/project/.env"]
    asyncio.run(execute())

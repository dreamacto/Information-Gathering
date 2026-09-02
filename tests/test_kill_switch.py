from authorized_assessment.orchestration.kill_switch import KillSwitch


def test_kill_switch_propagates_and_is_idempotent():
    switch = KillSwitch(); child = switch.child_event()
    first = switch.request("stop"); second = switch.request("again")
    assert child.is_set() and switch.is_set() and first.generation == second.generation
    assert switch.reason == "again"
    assert switch.clear().active is False

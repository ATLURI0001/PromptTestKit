from scripts.prompt_pass_rate_rotary import PromptPassRateRotary


def test_prompt_pass_rate_rotary():
    r = PromptPassRateRotary(4)
    r.record(True, 12.0)
    r.record(False, 20.0)
    r.record(True, 10.0)
    r.record(True, 15.0)
    assert r.get_pass_rate_pct() == 75.0

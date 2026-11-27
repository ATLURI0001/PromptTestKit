from scripts.yaml_inject_sentinel import has_yaml_injection


def test_yaml_inject_sentinel():
    assert has_yaml_injection("!!python/object/apply:os.system ['id']") is True
    assert has_yaml_injection("name: safe_prompt") is False

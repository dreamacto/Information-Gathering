from exercise_runtime import Target, domain_hint_from_targets


def t(host: str) -> Target:
    return Target(url=f"https://{host}/", host=host)


def test_registered_parent_extracted():
    assert domain_hint_from_targets([t("www.gxcic.net")]) == "gxcic.net"
    assert domain_hint_from_targets([t("taizhou.gov.cn")]) == "taizhou.gov.cn"


def test_second_level_suffix_keeps_three_labels():
    assert domain_hint_from_targets([t("oa.example.gov.cn")]) == "example.gov.cn"


def test_empty_or_hostless_returns_blank():
    assert domain_hint_from_targets([]) == ""
    assert domain_hint_from_targets([Target(url="https://127.0.0.1/", host="")]) == ""

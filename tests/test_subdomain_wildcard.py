from subdomain_bruteforce_controlled import split_wildcard_results


def test_wildcard_noise_is_dropped_real_host_kept():
    host_ips = {
        "api.example.cn": {"1.2.3.4"},
        "shop.example.cn": {"1.2.3.4", "5.6.7.8"},
        "mail.example.cn": {"9.9.9.9"},
    }
    wildcard_map = {"example.cn": ["1.2.3.4"]}
    kept, dropped = split_wildcard_results(host_ips, wildcard_map)
    assert kept == ["mail.example.cn", "shop.example.cn"]
    assert dropped == ["api.example.cn"]


def test_no_wildcard_keeps_everything():
    host_ips = {"a.test": {"1.1.1.1"}, "b.test": {"2.2.2.2"}}
    kept, dropped = split_wildcard_results(host_ips, {})
    assert kept == ["a.test", "b.test"]
    assert dropped == []


def test_unknown_ip_outside_wildcard_answer_is_kept():
    host_ips = {"x.example.com": {"10.0.0.1"}}
    wildcard_map = {"example.com": ["1.2.3.4"]}
    kept, _ = split_wildcard_results(host_ips, wildcard_map)
    assert kept == ["x.example.com"]

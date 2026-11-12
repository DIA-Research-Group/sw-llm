from ips.records import Labeler, llm_view, normalize, parse_ts


def test_normalize_nested_logstash_doc():
    doc = {"@timestamp": "2026-11-11T12:23:04.296457976Z", "type": "syslog",
           "nginx": {"remote_addr": "172.30.0.101", "status": 200, "request_time": 0.005,
                     "body_bytes_sent": "9984", "request_uri": "/x", "request_method": "GET"}}
    rec = normalize(doc, Labeler(["172.30.0.101"], []))
    assert rec["status"] == 200 and rec["body_bytes_sent"] == 9984.0
    assert rec["label"] == "attack"
    assert abs(rec["ts"] - parse_ts("2026-11-11T12:23:04.296457Z")) < 1e-6
    assert "label" not in llm_view(rec) and "ts" not in llm_view(rec)


def test_normalize_drops_non_http():
    assert normalize({"@timestamp": "2026-01-01T00:00:00Z", "message": "juice"}) is None


def test_normalize_flat_legacy():
    rec = normalize({"remote_addr": "1.2.3.4", "status": "404", "request_time": "-", "ts": 5.0})
    assert rec["status"] == 404 and rec["request_time"] is None and rec["ts"] == 5.0

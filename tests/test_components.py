from collections import Counter

from ips.conn import parse_proc_net_tcp
from ips.kg import KnowledgeGraph, MemoryStore, aggregate, endpoint_template, features_of, payload_tokens
from ips.layer2 import parse_decision_json


def test_parse_proc_net_tcp():
    text = """  sl  local_address rem_address   st
   0: 0A1E00AC:0050 6600 1EAC:D431 01
   1: 0A1E00AC:0050 66001EAC:D432 01
   2: 0A1E00AC:0050 33001EAC:D433 01
   3: 0A1E00AC:0050 33001EAC:D434 06
   4: 00000000:0050 00000000:0000 0A"""
    # 0x66001EAC little-endian = 172.30.0.102 ; 0x33001EAC = 172.30.0.51
    text = text.replace("6600 1EAC", "66001EAC")
    c = parse_proc_net_tcp(text)
    assert c == Counter({"172.30.0.102": 2, "172.30.0.51": 1})


def test_parse_proc_net_tcp6_mapped():
    line = "   0: 0000000000000000FFFF00000A1E00AC:0050 0000000000000000FFFF000066001EAC:D431 01"
    assert parse_proc_net_tcp("sl\n" + line) == Counter({"172.30.0.102": 1})


def test_endpoint_template_and_tokens():
    assert endpoint_template("/api/Users/42?x=1&a=2") == "/api/Users/{n}?a&x"
    assert set(payload_tokens({"request_uri": "/search?q=' OR 1=1--"})) >= {"sqli"}
    assert "jndi" in payload_tokens({"http_user_agent": "${jndi:ldap://x/a}"})


def test_parse_decision_variants():
    assert parse_decision_json('```json\n{"ataque_detectado": true}\n```')["ataque_detectado"] is True
    assert parse_decision_json('Here: {"ataque_detectado": false} ok')["ataque_detectado"] is False


class Cfg:
    kg_similarity_threshold = 0.5
    kg_hunt_min_requests = 5
    kg_hunt_min_error_ratio = 0.5
    conn_per_ip_threshold = 50


def test_kg_signature_matches_similar_ip():
    kg = KnowledgeGraph(MemoryStore(), Cfg())
    attack = lambda ip: [{"remote_addr": ip, "request_uri": u, "status": 404, "ts": 1.0,
                          "http_user_agent": "ZAP/2.15", "request_method": "GET"}
                         for u in ("/../../etc/passwd", "/s?q=' OR 1=1--", "/admin")]
    benign = [{"remote_addr": "172.30.0.51", "request_uri": "/", "status": 200, "ts": 1.0,
               "http_user_agent": "Firefox/115", "request_method": "GET"}]
    kg.ingest(attack("172.30.0.103") + benign)

    class D:
        model_returned = attack_type = explanation = None

    kg.feedback("172.30.0.103", D(), [], 1.0)
    kg.ingest(attack("172.30.0.104"))
    blocked = {"172.30.0.103"}
    match = kg.match_window(attack("172.30.0.104") + benign, exclude=lambda ip: ip in blocked)
    assert match and match[0] == "172.30.0.104"
    assert kg.match_window(benign, exclude=lambda ip: ip in blocked) is None


def test_kg_hunt_flags_connections_once():
    kg = KnowledgeGraph(MemoryStore(), Cfg())
    kg.ingest([{"kind": "conn", "remote_addr": "172.30.0.102", "open_connections": 400}])
    first = kg.hunt(exclude=lambda ip: False)
    assert first and first[0]["max_open_connections"] == 400
    assert kg.hunt(exclude=lambda ip: False) == []

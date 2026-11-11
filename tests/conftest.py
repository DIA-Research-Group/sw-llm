import json
import random

import pytest


def make_logs(seed=0, t0=1_800_000_000.0, duration=120, attack_start=60):
    """Trafego sintetico: 3 IPs benignos o tempo todo e 1 atacante apos attack_start."""
    rng = random.Random(seed)
    out = []
    t = t0
    while t < t0 + duration:
        for ip in ("172.30.0.51", "172.30.0.52", "172.30.0.53"):
            if rng.random() < 0.6:
                out.append({"ts": t + rng.random(), "remote_addr": ip, "request_method": "GET",
                            "request_uri": rng.choice(["/", "/api/Products", "/rest/user/whoami"]),
                            "status": 200, "request_time": rng.uniform(0.001, 0.05),
                            "body_bytes_sent": rng.choice([11, 13212, 26411]),
                            "http_user_agent": "Mozilla/5.0 Firefox/115.0"})
        if t >= t0 + attack_start:
            for _ in range(12):
                out.append({"ts": t + rng.random(), "remote_addr": "172.30.0.101", "request_method": "GET",
                            "request_uri": rng.choice(["/rest/products/search?q=' OR 1=1--", "/../../etc/passwd",
                                                       "/ftp/x%2e%2e", "/api/Users/" + str(rng.randint(1, 99))]),
                            "status": rng.choice([400, 401, 403, 404, 500]),
                            "request_time": rng.uniform(0.001, 3.0), "body_bytes_sent": rng.randint(0, 3000),
                            "http_user_agent": "Mozilla/5.0 ZAP/2.15"})
        t += 1.0
    return sorted(out, key=lambda r: r["ts"])


@pytest.fixture
def jsonl_logs(tmp_path):
    path = tmp_path / "logs.jsonl"
    with open(path, "w") as fh:
        for rec in make_logs():
            fh.write(json.dumps(rec) + "\n")
    return str(path)

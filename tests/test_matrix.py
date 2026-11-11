from ips.matrix import expand_design


def test_design_dedup_and_names():
    order = ["a", "b", "c"]
    out = dict(expand_design(order, ["baseline", "isolated", "cumulative", "leave_one_out"]))
    assert out["baseline"] == []
    assert out["+a"] == ["a"] and out["+b"] == ["b"] and out["+c"] == ["c"]
    # cumulativo {a,b} coincide com leave-one-out sem c -> nome canonico unico
    assert out["all-c"] == ["a", "b"] and "+a+b" not in out
    assert out["all"] == ["a", "b", "c"]
    assert out["all-a"] == ["b", "c"] and out["all-b"] == ["a", "c"]
    assert len(out) == 8


def test_full_factorial():
    assert len(expand_design(["a", "b", "c", "d"], ["full_factorial"])) == 16

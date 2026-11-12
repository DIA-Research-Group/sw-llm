"""Expansao do desenho experimental (ablacao).

Desenhos suportados (combinaveis):

* ``baseline``       – nenhum fator ligado (arquitetura original);
* ``isolated``       – cada fator sozinho sobre a baseline (efeito individual);
* ``cumulative``     – fatores empilhados na ordem declarada (efeito acumulado);
* ``leave_one_out``  – todos os fatores menos um (contribuicao marginal);
* ``full_factorial`` – todas as 2^k combinacoes.

Configuracoes repetidas (mesmo conjunto de fatores) sao deduplicadas: o nome
canonico depende apenas do conjunto, o que permite a analise reconstruir as
comparacoes "antes/depois" a partir da coluna de fatores.
"""
from __future__ import annotations

from itertools import combinations


def canonical_name(factors: list[str], order: list[str]) -> str:
    chosen = [f for f in order if f in set(factors)]
    if not chosen:
        return "baseline"
    if len(chosen) == len(order) and len(order) > 1:
        return "all"
    missing = [f for f in order if f not in set(factors)]
    if len(order) > 2 and len(missing) == 1:
        return f"all-{missing[0]}"
    return "+" + "+".join(chosen)


def close_requirements(factors: list[str], requires: dict[str, list[str]]) -> set[str]:
    out = set(factors)
    changed = True
    while changed:
        changed = False
        for f in list(out):
            for dep in requires.get(f, []):
                if dep not in out:
                    out.add(dep)
                    changed = True
    return out


def expand_design(order: list[str], design: list[str],
                  requires: dict[str, list[str]] | None = None) -> list[tuple[str, list[str]]]:
    """``requires`` (ex.: {"kgsafe": ["kg"]}) adiciona dependencias a cada
    conjunto antes da deduplicacao: ``+kgsafe`` vira ``+kg+kgsafe`` e
    ``all-kg`` coincide com ``all`` (e e descartado)."""
    unknown = set(design) - {"baseline", "isolated", "cumulative", "leave_one_out", "full_factorial"}
    if unknown:
        raise ValueError(f"Desenho desconhecido: {sorted(unknown)}")
    sets: list[list[str]] = []
    if "baseline" in design:
        sets.append([])
    if "isolated" in design:
        sets.extend([f] for f in order)
    if "cumulative" in design:
        sets.extend(order[:k] for k in range(1, len(order) + 1))
    if "leave_one_out" in design:
        sets.extend([g for g in order if g != f] for f in order)
    if "full_factorial" in design:
        for k in range(len(order) + 1):
            sets.extend(list(c) for c in combinations(order, k))

    seen: set[frozenset[str]] = set()
    out = []
    for factor_set in sets:
        key = frozenset(close_requirements(factor_set, requires or {}))
        if key in seen:
            continue
        seen.add(key)
        ordered = [f for f in order if f in key]
        out.append((canonical_name(ordered, order), ordered))
    return out

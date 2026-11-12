"""Analise estatistica dos experimentos.

    python -m ips.analyze runs/<experimento>            # gera runs/<experimento>/analysis/
    python -m ips.analyze runs/<experimento> --metrics tokens_total,ttm_s

Para cada execucao calcula metricas de custo, deteccao, Camada 1 (#20) e
recursos (#21). Agrega por (cenario, configuracao) com media, desvio e IC 95%
(t de Student) e compara configuracoes "antes/depois":

* ``isolated``   – cada configuracao vs ``baseline``;
* ``cumulative`` – cada passo do empilhamento vs o passo anterior;
* ``loo``        – ``all`` vs ``all-<fator>`` (contribuicao marginal);
* ``refinement`` – fator que refina outro (``requires``) vs a dependencia
  (ex.: ``+kg`` -> ``+kg+kgsafe``);
* ``arm``        – bracos de comparacao (LLM puro, CRS...) vs ``baseline``.

Testes: t de Welch (bilateral), Mann-Whitney U (robustez), d de Cohen e
correcao de Holm-Bonferroni por (cenario, metrica, tipo de comparacao).
"""
from __future__ import annotations

import argparse
import glob
import json
import math
import os
from typing import Any

import numpy as np
import pandas as pd

KEY_METRICS = [
    "llm_calls", "tokens_total", "cost_total", "latency_mean", "latency_p95", "logs_to_llm_ratio",
    "detected", "ttm_s", "attack_ip_recall", "fp_ips", "window_precision", "window_recall", "window_f1",
    "ip_accuracy", "attack_block_rate", "benign_block_rate", "kg_decisions",
    "iforest_precision", "iforest_recall", "iforest_f1", "iforest_fpr", "iforest_auc_roc",
    "gnn_recall", "gnn_fpr", "layer1_recall", "layer1_fpr",
    "cpu_total_mean", "mem_total_max_mb", "detector_cpu_mean", "detector_mem_max_mb",
]
# Metricas em que "maior e melhor" (para o sentido das setas no relatorio)
HIGHER_IS_BETTER = {"detected", "attack_ip_recall", "window_precision", "window_recall", "window_f1", "ip_accuracy",
                    "attack_block_rate", "iforest_precision", "iforest_recall", "iforest_f1", "iforest_auc_roc",
                    "gnn_recall", "layer1_recall", "kg_decisions"}


def _read(path: str) -> pd.DataFrame:
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return pd.DataFrame()
    return pd.read_csv(path)


def _binary(y_true: np.ndarray, y_pred: np.ndarray, prefix: str) -> dict[str, float]:
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else np.nan
    rec = tp / (tp + fn) if tp + fn else np.nan
    f1 = 2 * prec * rec / (prec + rec) if prec == prec and rec == rec and prec + rec else np.nan
    return {f"{prefix}_tp": tp, f"{prefix}_fp": fp, f"{prefix}_tn": tn, f"{prefix}_fn": fn,
            f"{prefix}_precision": prec, f"{prefix}_recall": rec, f"{prefix}_f1": f1,
            f"{prefix}_fpr": fp / (fp + tn) if fp + tn else np.nan}


def run_metrics(rdir: str) -> dict[str, Any]:
    meta = json.load(open(os.path.join(rdir, "run.json")))
    m: dict[str, Any] = {"config": meta["config"], "scenario": meta["scenario"], "rep": meta["rep"],
                         "factors": "+".join(meta.get("factors") or []), "run_dir": rdir,
                         "mode": meta.get("mode", "live")}
    win = _read(os.path.join(rdir, "windows.csv"))
    enf = _read(os.path.join(rdir, "enforcement.csv"))
    l1 = _read(os.path.join(rdir, "layer1.csv"))
    res = _read(os.path.join(rdir, "resources.csv"))
    conns = _read(os.path.join(rdir, "connections.csv"))

    # ---- custo / Camada 2
    llm = win[win["decision_source"].isin(["llm", "kg_hunt"])] if not win.empty else win
    m["windows"] = len(win)
    m["llm_calls"] = len(llm)
    m["llm_errors"] = int((llm["status"] != "ok").sum()) if not llm.empty else 0
    m["tokens_total"] = float(llm["total_tokens"].fillna(0).sum()) if not llm.empty else 0.0
    m["tokens_per_call"] = m["tokens_total"] / m["llm_calls"] if m["llm_calls"] else np.nan
    m["cost_total"] = float(llm["cost_usd"].fillna(0).sum()) if "cost_usd" in llm and not llm.empty else 0.0
    lat = llm.loc[llm["status"] == "ok", "latency_s"] if not llm.empty else pd.Series(dtype=float)
    m["latency_mean"] = float(lat.mean()) if len(lat) else np.nan
    m["latency_p95"] = float(lat.quantile(0.95)) if len(lat) else np.nan
    m["kg_decisions"] = int((win["decision_source"] == "kg").sum()) if not win.empty else 0
    total_logs = len(l1)
    sent = float(win["n_logs_sent"].fillna(0).sum()) if not win.empty else 0.0
    m["logs_total"] = total_logs
    m["logs_to_llm_ratio"] = sent / total_logs if total_logs else np.nan
    models = llm["model_returned"].dropna().unique().tolist() if not llm.empty else []
    m["models_returned"] = ";".join(sorted(map(str, models)))

    # ---- deteccao / mitigacao
    labelled = l1[l1["label"].isin(["attack", "benign"])] if not l1.empty else l1
    attack_seen = set(labelled.loc[labelled["label"] == "attack", "remote_addr"]) if not labelled.empty else set()
    if not conns.empty:
        attack_seen |= set(conns.loc[conns["label"] == "attack", "remote_addr"])
    acts = enf[enf["action"].isin(["block", "shadow_block"])] if not enf.empty else enf
    att_enf = acts[acts["label"] == "attack"] if not acts.empty else acts
    m["attack_ips_seen"] = len(attack_seen)
    m["detected"] = float(len(att_enf) > 0)
    m["attack_ip_recall"] = len(set(att_enf["ip"]) & attack_seen) / len(attack_seen) if attack_seen else np.nan
    # fp_ips: so IPs benignos conhecidos; IPs sem rotulo (ex.: gateway do Docker,
    # sondas do runner) ficam em unknown_ips para nao inflar os falsos positivos.
    m["fp_ips"] = int(acts.loc[acts["label"] == "benign", "ip"].nunique()) if not acts.empty else 0
    m["unknown_ips_blocked"] = int(acts.loc[acts["label"] == "unknown", "ip"].nunique()) if not acts.empty else 0
    first_attack = []
    if not labelled.empty:
        first_attack.append(labelled.loc[labelled["label"] == "attack", "ts"].min())
    if not conns.empty:
        first_attack.append(conns.loc[(conns["label"] == "attack") & (conns["open_connections"] > 0), "ts"].min())
    first_attack = [t for t in first_attack if t == t]
    m["ttm_s"] = float(att_enf["ts"].min() - min(first_attack)) if len(att_enf) and first_attack else np.nan

    if not win.empty:
        gt = (win["n_attack_logs"].fillna(0) > 0).astype(int).to_numpy()
        pred = win["attack_detected"].map(lambda v: str(v).lower() == "true").astype(int).to_numpy()
        b = _binary(gt, pred, "window")
        m.update({k: b[k] for k in ("window_precision", "window_recall", "window_f1")})
        pos = win[win["attack_detected"].map(lambda v: str(v).lower() == "true") & win["target_label"].notna()]
        m["ip_accuracy"] = float((pos["target_label"] == "attack").mean()) if len(pos) else np.nan

    if not labelled.empty:
        blocked = labelled["status"] == 403
        for lab in ("attack", "benign"):
            sel = labelled["label"] == lab
            m[f"{lab}_block_rate"] = float(blocked[sel].mean()) if sel.any() else np.nan

        # ---- Camada 1 (#20)
        y = (labelled["label"] == "attack").astype(int).to_numpy()
        if labelled["iforest_pred"].notna().any():
            m.update(_binary(y, labelled["iforest_pred"].fillna(0).astype(int).to_numpy(), "iforest"))
            try:
                from sklearn.metrics import average_precision_score, roc_auc_score

                if 0 < y.sum() < len(y):
                    score = -labelled["iforest_score"].to_numpy()
                    m["iforest_auc_roc"] = float(roc_auc_score(y, score))
                    m["iforest_auc_pr"] = float(average_precision_score(y, score))
            except ImportError:
                pass
        if "gnn_pred" in labelled and labelled["gnn_pred"].notna().any():
            m.update(_binary(y, labelled["gnn_pred"].fillna(0).astype(int).to_numpy(), "gnn"))
        l1_pred = (labelled["iforest_pred"].fillna(0).astype(int) | labelled.get("gnn_pred", 0).fillna(0).astype(int))
        m.update({k: v for k, v in _binary(y, l1_pred.to_numpy(), "layer1").items()
                  if k in ("layer1_recall", "layer1_fpr", "layer1_precision")})

    # ---- recursos (#21)
    if not res.empty:
        res["cpu_pct"] = pd.to_numeric(res["cpu_pct"], errors="coerce")
        res["mem_bytes"] = pd.to_numeric(res["mem_bytes"], errors="coerce")
        infra = res[~res["container"].str.contains("attacker|zap|slowloris|benign|csic", regex=True)]
        per = infra.groupby("container").agg(cpu=("cpu_pct", "mean"), mem=("mem_bytes", "max"))
        m["cpu_total_mean"] = float(per["cpu"].sum())
        m["mem_total_max_mb"] = float(per["mem"].sum() / 2**20)
        for name, row in per.iterrows():
            short = name.replace("ips-", "").replace("-", "_")
            m[f"{short}_cpu_mean"] = float(row["cpu"])
            m[f"{short}_mem_max_mb"] = float(row["mem"] / 2**20)
    return m


def collect(exp_dir: str) -> pd.DataFrame:
    rows = []
    for done in sorted(glob.glob(os.path.join(exp_dir, "*", "*", "rep-*", "DONE"))):
        try:
            rows.append(run_metrics(os.path.dirname(done)))
        except Exception as exc:  # execucao corrompida nao derruba a analise
            print(f"[aviso] ignorando {os.path.dirname(done)}: {exc}")
    return pd.DataFrame(rows)


# ------------------------------------------------------------------ estatistica
def ci95(values: pd.Series) -> tuple[float, float, float, int]:
    v = values.dropna().astype(float)
    n = len(v)
    if n == 0:
        return np.nan, np.nan, np.nan, 0
    mean = float(v.mean())
    if n < 2:
        return mean, np.nan, np.nan, n
    from scipy import stats

    half = stats.t.ppf(0.975, n - 1) * v.std(ddof=1) / math.sqrt(n)
    return mean, mean - half, mean + half, n


def summarize(df: pd.DataFrame, metrics: list[str]) -> pd.DataFrame:
    out = []
    for (scen, cfg), g in df.groupby(["scenario", "config"]):
        row = {"scenario": scen, "config": cfg, "factors": g["factors"].iloc[0], "n": len(g)}
        for mt in metrics:
            if mt not in g:
                continue
            mean, lo, hi, n = ci95(g[mt])
            row[f"{mt}_mean"], row[f"{mt}_ci_lo"], row[f"{mt}_ci_hi"] = mean, lo, hi
            row[f"{mt}_std"] = float(g[mt].std(ddof=1)) if n > 1 else np.nan
        out.append(row)
    return pd.DataFrame(out)


def comparison_pairs(configs: list[str], factor_order: list[str], arms: list[str],
                     requires: dict[str, list[str]] | None = None) -> list[tuple[str, str, str]]:
    from ips.matrix import canonical_name, close_requirements

    def canonical_name_req(fs, order):
        closed = close_requirements(fs, requires or {})
        return canonical_name([f for f in order if f in closed], order)

    have = set(configs)
    pairs = []
    for c in configs:
        if c != "baseline" and c not in arms and "baseline" in have:
            pairs.append(("isolated" if c.startswith("+") and c.count("+") == 1 else "vs_baseline", "baseline", c))
    prev = "baseline"
    for k in range(1, len(factor_order) + 1):
        cur = canonical_name_req(factor_order[:k], factor_order)
        if cur in have and prev in have and k > 1:
            pairs.append(("cumulative", prev, cur))
        prev = cur
    if "all" in have:
        for f in factor_order:
            loo = canonical_name_req([g for g in factor_order if g != f], factor_order)
            if loo in have and loo != "all":
                pairs.append(("loo", loo, "all"))
    # fatores que refinam outro (requires): efeito do refinamento sobre a dependencia
    for f, deps in (requires or {}).items():
        if not deps:
            continue
        before, after = canonical_name_req(deps, factor_order), canonical_name_req([f], factor_order)
        if before in have and after in have and before != after:
            pairs.append(("refinement", before, after))
    for a in arms:
        if a in have and "baseline" in have:
            pairs.append(("arm", "baseline", a))
    return pairs


def holm(pvals: list[float]) -> list[float]:
    idx = [i for i, p in enumerate(pvals) if p == p]
    order = sorted(idx, key=lambda i: pvals[i])
    adj = [np.nan] * len(pvals)
    running = 0.0
    m = len(order)
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvals[i]))
        adj[i] = running
    return adj


def compare(df: pd.DataFrame, metrics: list[str], factor_order: list[str], arms: list[str],
            paired: bool = False, requires: dict[str, list[str]] | None = None) -> pd.DataFrame:
    """Compara pares de configuracoes. ``paired=True`` (replay sobre o mesmo
    trafego) usa t pareado e Wilcoxon, alinhando por repeticao."""
    from scipy import stats

    rows = []
    for scen, g in df.groupby("scenario"):
        pairs = comparison_pairs(sorted(g["config"].unique()), factor_order, arms, requires)
        for kind, before, after in pairs:
            a = g[g["config"] == before]
            b = g[g["config"] == after]
            for mt in metrics:
                if mt not in g:
                    continue
                if paired:
                    j = a[["rep", mt]].merge(b[["rep", mt]], on="rep", suffixes=("_a", "_b")).dropna()
                    x, y = j[f"{mt}_a"].astype(float), j[f"{mt}_b"].astype(float)
                else:
                    x, y = a[mt].dropna().astype(float), b[mt].dropna().astype(float)
                row = {"scenario": scen, "comparison": kind, "before": before, "after": after, "metric": mt,
                       "n_before": len(x), "n_after": len(y),
                       "mean_before": x.mean() if len(x) else np.nan, "mean_after": y.mean() if len(y) else np.nan}
                row["delta"] = row["mean_after"] - row["mean_before"]
                row["delta_pct"] = row["delta"] / abs(row["mean_before"]) * 100 if row["mean_before"] else np.nan
                if paired and len(x) >= 2 and (y.to_numpy() - x.to_numpy()).std() > 0:
                    diff = y.to_numpy() - x.to_numpy()
                    row["p_welch"] = float(stats.ttest_rel(y, x).pvalue)  # t pareado
                    row["p_mannwhitney"] = float(stats.wilcoxon(diff).pvalue)  # Wilcoxon pareado
                    row["cohens_d"] = float(diff.mean() / diff.std(ddof=1))  # d_z
                elif not paired and len(x) >= 2 and len(y) >= 2 and (x.std() > 0 or y.std() > 0):
                    row["p_welch"] = float(stats.ttest_ind(x, y, equal_var=False).pvalue)
                    row["p_mannwhitney"] = float(stats.mannwhitneyu(x, y, alternative="two-sided").pvalue)
                    pooled = math.sqrt(((len(x) - 1) * x.var() + (len(y) - 1) * y.var()) / (len(x) + len(y) - 2))
                    row["cohens_d"] = row["delta"] / pooled if pooled else np.nan
                else:
                    row["p_welch"] = row["p_mannwhitney"] = row["cohens_d"] = np.nan
                rows.append(row)
    out = pd.DataFrame(rows)
    if out.empty:
        return out
    out["p_holm"] = np.nan
    for _, idx in out.groupby(["scenario", "metric", "comparison"]).groups.items():
        out.loc[idx, "p_holm"] = holm(out.loc[idx, "p_welch"].tolist())
    out["significant"] = out["p_holm"] < 0.05
    return out


# ---------------------------------------------------------------------- graficos
def plot(df: pd.DataFrame, summary: pd.DataFrame, outdir: str, metrics: list[str], order: list[str]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(outdir, exist_ok=True)
    for scen, s in summary.groupby("scenario"):
        s = s.set_index("config").reindex([c for c in order if c in set(s["config"])]).reset_index()
        for mt in metrics:
            col = f"{mt}_mean"
            if col not in s or s[col].isna().all():
                continue
            fig, ax = plt.subplots(figsize=(max(6, 0.55 * len(s)), 4))
            err = np.vstack([s[col] - s[f"{mt}_ci_lo"], s[f"{mt}_ci_hi"] - s[col]])
            colors = ["#888888" if c == "baseline" else "#1f77b4" for c in s["config"]]
            ax.bar(s["config"], s[col], yerr=np.nan_to_num(err), capsize=3, color=colors, edgecolor=".2")
            ax.set_title(f"{mt} — {scen} (média ± IC95%)")
            ax.tick_params(axis="x", rotation=60)
            fig.tight_layout()
            fig.savefig(os.path.join(outdir, f"{scen}__{mt}.png"), dpi=150)
            plt.close(fig)

    # #20: distribuicao dos escores do iForest por rotulo (baseline de cada cenario)
    for scen, g in df[df["config"] == "baseline"].groupby("scenario"):
        frames = [_read(os.path.join(r, "layer1.csv")) for r in g["run_dir"]]
        frames = [f for f in frames if not f.empty]
        if not frames:
            continue
        l1 = pd.concat(frames)
        l1 = l1[l1["label"].isin(["attack", "benign"])]
        fig, ax = plt.subplots(figsize=(6, 4))
        for lab, color in (("benign", "#1f77b4"), ("attack", "#d62728")):
            ax.hist(l1.loc[l1["label"] == lab, "iforest_score"], bins=60, alpha=0.6, label=lab, color=color, density=True)
        ax.axvline(0, color="k", ls="--", lw=1)
        ax.set_xlabel("decision_function do iForest (< 0 = anomalia)")
        ax.set_title(f"Escores do iForest por rótulo — {scen}")
        ax.legend()
        fig.tight_layout()
        fig.savefig(os.path.join(outdir, f"{scen}__iforest_scores.png"), dpi=150)
        plt.close(fig)


def write_report(summary: pd.DataFrame, comps: pd.DataFrame, path: str, metrics: list[str],
                 order: list[str] | None = None) -> None:
    if order:
        rank = {c: i for i, c in enumerate(order)}
        summary = summary.assign(_o=summary["config"].map(lambda c: rank.get(c, len(rank)))).sort_values(["scenario", "_o"])
    lines = ["# Relatório do experimento", "",
             "Média [IC 95%] por configuração; comparações com teste t (Welch, ou pareado no replay) "
             "e correção de Holm-Bonferroni.", ""]
    for scen, s in summary.groupby("scenario"):
        lines += [f"## Cenário `{scen}`", "", "| config | n | " + " | ".join(metrics) + " |",
                  "|---|---|" + "---|" * len(metrics)]
        for _, r in s.iterrows():
            cells = []
            for mt in metrics:
                mean = r.get(f"{mt}_mean")
                lo, hi = r.get(f"{mt}_ci_lo"), r.get(f"{mt}_ci_hi")
                cells.append("—" if mean != mean else (f"{mean:.3g} [{lo:.3g}, {hi:.3g}]" if lo == lo else f"{mean:.3g}"))
            lines.append(f"| {r['config']} | {r['n']} | " + " | ".join(cells) + " |")
        lines.append("")
        if not comps.empty:
            sig = comps[(comps["scenario"] == scen) & comps["significant"].fillna(False)]
            if len(sig):
                lines += ["Diferenças significativas (p_holm < 0,05):", ""]
                for _, c in sig.iterrows():
                    better = (c["delta"] > 0) == (c["metric"] in HIGHER_IS_BETTER)
                    lines.append(f"- {c['comparison']}: `{c['before']}` → `{c['after']}` | {c['metric']}: "
                                 f"{c['mean_before']:.3g} → {c['mean_after']:.3g} ({c['delta_pct']:+.1f}%, "
                                 f"d={c['cohens_d']:.2f}, p={c['p_holm']:.3g}) {'melhora' if better else 'piora'}")
                lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Analise estatistica de um experimento")
    ap.add_argument("exp_dir")
    ap.add_argument("--metrics", help="lista separada por virgula (padrao: principais)")
    ap.add_argument("--out", help="diretorio de saida (padrao: <exp_dir>/analysis)")
    args = ap.parse_args(argv)

    df = collect(args.exp_dir)
    if df.empty:
        print("Nenhuma execucao concluida encontrada.")
        return 1
    outdir = args.out or os.path.join(args.exp_dir, "analysis")
    os.makedirs(outdir, exist_ok=True)
    metrics = args.metrics.split(",") if args.metrics else [m for m in KEY_METRICS if m in df]

    factor_order, arms, order, requires = [], [], sorted(df["config"].unique()), {}
    exp_yaml = os.path.join(args.exp_dir, "experiment.yaml")
    if os.path.exists(exp_yaml):
        from ips.config import Experiment

        exp = Experiment.load(exp_yaml)
        factor_order, arms, requires = exp.factor_order, list(exp.arms), exp.requires
        order = [s.name for s in exp.runs()]

    df.to_csv(os.path.join(outdir, "runs.csv"), index=False)
    summary = summarize(df, metrics)
    summary.to_csv(os.path.join(outdir, "summary.csv"), index=False)
    paired = bool((df["mode"] == "replay").all())
    comps = compare(df, metrics, factor_order, arms, paired=paired, requires=requires)
    comps["test"] = "paired t / Wilcoxon" if paired else "Welch t / Mann-Whitney"
    comps.to_csv(os.path.join(outdir, "comparisons.csv"), index=False)
    plot(df, summary, os.path.join(outdir, "figures"), metrics, order)
    write_report(summary, comps, os.path.join(outdir, "report.md"),
                 [m for m in ("tokens_total", "llm_calls", "ttm_s", "attack_ip_recall", "fp_ips",
                              "iforest_f1", "cpu_total_mean") if m in metrics], order)
    print(f"{len(df)} execucoes analisadas -> {outdir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

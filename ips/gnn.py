"""Deteccao de anomalias estruturais com GNN (#13, fase 4).

Implementa um autoencoder de grafo no estilo DOMINANT (Ding et al., SDM 2019):
encoder GCN de 2 camadas, decoder de atributos (GCN) e decoder de estrutura
(produto interno). O escore de anomalia de um no e a combinacao dos erros de
reconstrucao de atributos e de estrutura.

Grafo: bipartido IP <-> template de endpoint, construido sobre fatias de
``gnn_slice_s`` segundos. O modelo e treinado nas fatias do periodo de
aquecimento (somente trafego benigno, antes do inicio do ataque) e, depois,
cada IP da fatia corrente com erro acima do limiar calibrado
(quantil ``gnn_quantile`` dos erros de treino) marca seus logs com
``gnn_pred=1``. No pipeline o GNN atua em OU com o iForest.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

import numpy as np

from ips.kg import endpoint_template, ua_family

log = logging.getLogger("ips.gnn")
N_FEATURES = 8


def _features(reqs: list[dict[str, Any]], other_key: str) -> list[float]:
    n = len(reqs)
    statuses = [int(r.get("status") or 0) for r in reqs]
    rts = [float(r.get("request_time") or 0) for r in reqs]
    sizes = [float(r.get("body_bytes_sent") or 0) for r in reqs]
    return [
        np.log1p(n),
        sum(s >= 400 for s in statuses) / n,
        np.log1p(np.mean(rts)),
        np.log1p(np.mean(sizes)),
        np.log1p(len({r[other_key] for r in reqs})),
        sum(400 <= s < 500 for s in statuses) / n,
        sum(s >= 500 for s in statuses) / n,
        np.log1p(len({ua_family(r.get("http_user_agent")) for r in reqs})),
    ]


def build_graph(records: list[dict[str, Any]]):
    """Retorna (ips, X, A) com nos [IPs..., endpoints...]."""
    by_ip: dict[str, list] = defaultdict(list)
    by_ep: dict[str, list] = defaultdict(list)
    for r in records:
        ip = r.get("remote_addr")
        if not ip or r.get("status") is None:
            continue
        rr = {**r, "_ep": endpoint_template(r.get("request_uri")), "_ip": ip}
        by_ip[ip].append(rr)
        by_ep[rr["_ep"]].append(rr)
    ips, eps = sorted(by_ip), sorted(by_ep)
    if not ips:
        return [], np.zeros((0, N_FEATURES)), np.zeros((0, 0))
    idx = {ip: i for i, ip in enumerate(ips)}
    idx.update({ep: len(ips) + j for j, ep in enumerate(eps)})
    n = len(ips) + len(eps)
    X = np.zeros((n, N_FEATURES))
    A = np.zeros((n, n))
    for ip, reqs in by_ip.items():
        X[idx[ip]] = _features(reqs, "_ep")
        for r in reqs:
            A[idx[ip], idx[r["_ep"]]] = 1.0
            A[idx[r["_ep"]], idx[ip]] = 1.0
    for ep, reqs in by_ep.items():
        X[idx[ep]] = _features(reqs, "_ip")
    return ips, X, A


class GNNScorer:
    def __init__(self, cfg):
        try:
            import torch  # noqa: F401
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("gnn: true exige PyTorch (pip install -r requirements-gnn.txt)") from exc
        self.cfg = cfg
        self.slice_s = cfg.gnn_slice_s
        self.buffer: list[dict[str, Any]] = []
        self.warm: list[dict[str, Any]] = []
        self.start: float | None = None
        self.model = None
        self.mu = self.sd = None
        self.threshold: float | None = None
        self.train_nodes = 0
        self.flagged_ips: set[str] = set()

    # ---------------------------------------------------------------- dados
    def observe(self, records: list[dict[str, Any]], now: float) -> None:
        if self.start is None:
            self.start = now
        http = [r for r in records if r.get("ts") is not None]
        if self.model is None:
            self.warm.extend(http)
            if now - self.start >= self.cfg.gnn_warmup_s:
                self.train()
        self.buffer.extend(http)
        cutoff = now - self.slice_s
        self.buffer = [r for r in self.buffer if r["ts"] >= cutoff]

    def _slices(self, records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
        if not records:
            return []
        t0 = min(r["ts"] for r in records)
        groups: dict[int, list] = defaultdict(list)
        for r in records:
            groups[int((r["ts"] - t0) // self.slice_s)].append(r)
        return [g for _, g in sorted(groups.items())]

    # ------------------------------------------------------------- modelo
    def _norm_adj(self, A):
        import torch

        A_hat = A + torch.eye(A.shape[0])
        d = A_hat.sum(1).pow(-0.5)
        return d[:, None] * A_hat * d[None, :]

    def _make_model(self):
        import torch
        from torch import nn

        hidden = self.cfg.gnn_hidden

        class Dominant(nn.Module):
            def __init__(self):
                super().__init__()
                self.e1 = nn.Linear(N_FEATURES, hidden)
                self.e2 = nn.Linear(hidden, hidden)
                self.d1 = nn.Linear(hidden, hidden)
                self.d2 = nn.Linear(hidden, N_FEATURES)

            def forward(self, X, An):
                h = torch.relu(An @ self.e1(X))
                z = torch.relu(An @ self.e2(h))
                xa = torch.relu(An @ self.d1(z))
                x_hat = An @ self.d2(xa)
                a_hat = torch.sigmoid(z @ z.T)
                return x_hat, a_hat

        return Dominant()

    def _errors(self, X, A, alpha: float = 0.8):
        import torch

        x_hat, a_hat = self.model(X, self._norm_adj(A))
        attr = ((X - x_hat) ** 2).sum(1).sqrt()
        struct = ((A - a_hat) ** 2).sum(1).sqrt()
        return alpha * attr + (1 - alpha) * struct

    def _tensor_graph(self, records):
        import torch

        ips, X, A = build_graph(records)
        if not ips:
            return ips, None, None
        X = (X - self.mu) / self.sd
        return ips, torch.tensor(X, dtype=torch.float32), torch.tensor(A, dtype=torch.float32)

    def train(self) -> None:
        import torch

        torch.manual_seed(self.cfg.iforest_random_state)
        graphs = [build_graph(s) for s in self._slices(self.warm)]
        graphs = [g for g in graphs if g[0]]
        if not graphs:
            log.warning("GNN: sem trafego no aquecimento; adiando treino")
            self.start = None
            self.warm = []
            return
        allX = np.vstack([g[1] for g in graphs])
        self.mu, self.sd = allX.mean(0), allX.std(0) + 1e-6
        tg = [(torch.tensor((X - self.mu) / self.sd, dtype=torch.float32), torch.tensor(A, dtype=torch.float32))
              for _, X, A in graphs]
        self.model = self._make_model()
        opt = torch.optim.Adam(self.model.parameters(), lr=5e-3)
        for _ in range(self.cfg.gnn_epochs):
            opt.zero_grad()
            loss = sum(self._errors(X, A).pow(2).mean() for X, A in tg) / len(tg)
            loss.backward()
            opt.step()
        self.model.eval()
        with torch.no_grad():
            ip_err = np.concatenate([
                self._errors(X, A)[: len(ips)].numpy() for (ips, _, _), (X, A) in zip(graphs, tg)
            ])
        self.train_nodes = int(sum(len(g[0]) for g in graphs))
        self.threshold = float(np.quantile(ip_err, self.cfg.gnn_quantile))
        log.info("GNN treinado: %d fatias, %d nos-IP, limiar=%.3f", len(graphs), self.train_nodes, self.threshold)
        self.warm = []

    # ------------------------------------------------------------- escore
    def score(self, records: list[dict[str, Any]], now: float) -> None:
        if self.model is None:
            return
        import torch

        ips, X, A = self._tensor_graph(self.buffer)
        if not ips:
            return
        with torch.no_grad():
            err = self._errors(X, A)[: len(ips)].numpy()
        by_ip = dict(zip(ips, err))
        for r in records:
            e = by_ip.get(r.get("remote_addr"))
            if e is None:
                continue
            r["gnn_score"] = float(e)
            r["gnn_pred"] = int(e > self.threshold)
            if r["gnn_pred"]:
                self.flagged_ips.add(r["remote_addr"])

    def summary(self) -> dict[str, Any]:
        return {"trained": self.model is not None, "threshold": self.threshold,
                "train_ip_nodes": self.train_nodes, "flagged_ips": sorted(self.flagged_ips)}

"""Camada 1: filtro estatistico (Isolation Forest).

Alem da predicao, expoe o escore continuo (``decision_function``) para que a
analise da #20 possa construir curvas ROC/PR e matrizes de confusao.

Modos de treino (``iforest_fit``):

* ``baseline_csv`` – original: ``trafego_base.csv`` filtrado (status 200, < 2 s);
* ``warmup`` – comeca com o modelo original e, ao fim do aquecimento (somente
  trafego benigno, antes do ataque), e retreinado com os logs reais do Nginx.
  Corrige a baseline idealizada (7 rotas, tempo medido no cliente, so 200).

Limiar (``iforest_threshold_quantile``): ``None`` usa ``predict`` com o
``contamination`` configurado; um valor q marca como anomalia os escores
abaixo do quantil q dos escores de treino (FPR esperado ~ q).
"""
from __future__ import annotations

import logging
import warnings
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

log = logging.getLogger("ips.layer1")


class IForestFilter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.features = list(cfg.iforest_features)
        self.model: IsolationForest | None = None
        self.threshold: float | None = None
        self.n_train = 0
        self.fitted_on = None
        self.warm: list[list[float]] = []
        self.warm_start: float | None = None

    # ----------------------------------------------------------------- treino
    def _fit(self, X: np.ndarray, source: str) -> None:
        model = IsolationForest(
            n_estimators=self.cfg.iforest_n_estimators,
            contamination=self.cfg.iforest_contamination,
            random_state=self.cfg.iforest_random_state,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            model.fit(X)
            q = self.cfg.iforest_threshold_quantile
            self.threshold = float(np.quantile(model.decision_function(X), q)) if q is not None else None
        self.model, self.n_train, self.fitted_on = model, len(X), source

    def fit_baseline(self, csv_path: str | None = None) -> int:
        df = pd.read_csv(csv_path or self.cfg.baseline_csv)
        for col in self.features:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        # Mesmo filtro do detector original: so trafego legitimo (200 e < 2 s)
        df = df[(df["request_time"] < 2.0) & (df["status"] == 200)].dropna(subset=self.features)
        self._fit(df[self.features].to_numpy(dtype=float), "baseline_csv")
        return self.n_train

    def observe(self, records: list[dict[str, Any]], now: float) -> None:
        """Acumula logs do aquecimento e retreina ao final (iforest_fit=warmup)."""
        if self.cfg.iforest_fit != "warmup" or self.fitted_on == "warmup":
            return
        if self.warm_start is None:
            self.warm_start = now
        self.warm.extend([[float(r[f]) for f in self.features] for r in records
                          if all(r.get(f) is not None for f in self.features)])
        if now - self.warm_start < self.cfg.iforest_warmup_s:
            return
        if len(self.warm) < self.cfg.iforest_min_warmup_samples:
            log.warning("iForest: so %d logs no aquecimento; mantendo modelo do CSV", len(self.warm))
            self.fitted_on = "warmup"  # nao tenta de novo
            self.warm = []
            return
        self._fit(np.array(self.warm), "warmup")
        log.info("iForest retreinado no aquecimento com %d logs (limiar=%s)", self.n_train, self.threshold)
        self.warm = []

    # ----------------------------------------------------------------- escore
    def score(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anota ``iforest_score``/``iforest_pred``/``anomaly_score`` e devolve os validos."""
        valid = [r for r in records if all(r.get(f) is not None for f in self.features)]
        if not valid:
            return []
        X = np.array([[float(r[f]) for f in self.features] for r in valid])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            scores = self.model.decision_function(X)
            if self.threshold is None:
                anomalous = self.model.predict(X) == -1
            else:
                anomalous = scores < self.threshold
        for rec, a, s in zip(valid, anomalous, scores):
            rec["anomaly_score"] = -1 if a else 1  # nome/semantica do detector original
            rec["iforest_pred"] = int(a)
            rec["iforest_score"] = float(s)
        return valid

"""Camada 1: filtro estatistico (Isolation Forest).

Alem da predicao, expoe o escore continuo (``decision_function``) para que a
analise da #20 possa construir curvas ROC/PR e matrizes de confusao.
"""
from __future__ import annotations

import warnings
from typing import Any

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


class IForestFilter:
    def __init__(self, cfg):
        self.cfg = cfg
        self.features = list(cfg.iforest_features)
        self.model: IsolationForest | None = None
        self.n_train = 0

    def fit_baseline(self, csv_path: str | None = None) -> int:
        df = pd.read_csv(csv_path or self.cfg.baseline_csv)
        for col in self.features:
            df[col] = pd.to_numeric(df[col], errors="coerce")
        # Mesmo filtro do detector original: so trafego legitimo (200 e < 2 s)
        df = df[(df["request_time"] < 2.0) & (df["status"] == 200)].dropna(subset=self.features)
        self.model = IsolationForest(
            n_estimators=self.cfg.iforest_n_estimators,
            contamination=self.cfg.iforest_contamination,
            random_state=self.cfg.iforest_random_state,
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            self.model.fit(df[self.features].to_numpy(dtype=float))
        self.n_train = len(df)
        return self.n_train

    def score(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anota ``iforest_score``/``iforest_pred``/``anomaly_score`` e devolve os validos."""
        valid = [r for r in records if all(r.get(f) is not None for f in self.features)]
        if not valid:
            return []
        X = np.array([[float(r[f]) for f in self.features] for r in valid])
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            preds = self.model.predict(X)
            scores = self.model.decision_function(X)
        for rec, p, s in zip(valid, preds, scores):
            rec["anomaly_score"] = int(p)  # nome/semantica do detector original
            rec["iforest_pred"] = int(p == -1)
            rec["iforest_score"] = float(s)
        return valid

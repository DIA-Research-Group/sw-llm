#!/bin/bash
# Execucao unica na condicao original do artigo (ZAP, sem trafego benigno, 10 min).
# Wrapper do runner de experimentos; para a matriz de ablacao completa use:
#   python -m ips.run experiments/ablation.yaml --list
set -euo pipefail
cd "$(dirname "$0")"

MODEL_IDENTIFIER="${MODELO_IA:-anthropic/claude-3-5-haiku}"
# 'active' (bloqueio real, comportamento original) ou 'log_only' (shadow, #18)
ENFORCEMENT_MODE="${ENFORCEMENT_MODE:-active}"
PYTHON="${PYTHON:-$( [ -x .venv/bin/python ] && echo .venv/bin/python || echo python3 )}"

echo "=========================================================="
echo "  EXPERIMENTO: $MODEL_IDENTIFIER (mitigacao: $ENFORCEMENT_MODE)"
echo "=========================================================="
"$PYTHON" -m ips.run experiments/legacy.yaml \
  --set "model=$MODEL_IDENTIFIER" --set "enforcement=$ENFORCEMENT_MODE" \
  --tag "${MODEL_IDENTIFIER}-${ENFORCEMENT_MODE}"
echo "[SUCCESS] Resultados em runs/legacy-*/"

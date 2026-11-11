#!/bin/bash
# Baixa o CSIC 2010 (#16) e garante que todos usam exatamente os mesmos arquivos.
#
#   datasets/fetch_csic.sh                 # via Kaggle CLI (precisa de ~/.kaggle/kaggle.json)
#   datasets/fetch_csic.sh /caminho/dados  # ou copia arquivos ja baixados (CSV do Kaggle ou
#                                          # os .txt originais: normalTrafficTraining.txt, ...)
#
# Na primeira vez grava datasets/csic2010.sha256 (versione esse arquivo); nas
# seguintes confere os arquivos contra ele e falha se algo divergir.
set -euo pipefail
cd "$(dirname "$0")"
DEST=csic2010
SUMS=csic2010.sha256
mkdir -p "$DEST"

if [ $# -ge 1 ]; then
  cp -v "$1"/*.{csv,txt} "$DEST"/ 2>/dev/null || true
elif command -v kaggle >/dev/null; then
  kaggle datasets download -d ispangler/csic-2010-web-application-attacks -p "$DEST" --unzip
else
  echo "Kaggle CLI nao encontrada. Instale (pip install kaggle) ou passe o diretorio com os arquivos." >&2
  exit 1
fi

shopt -s nullglob
files=("$DEST"/*.csv "$DEST"/*.txt)
[ ${#files[@]} -gt 0 ] || { echo "Nenhum .csv/.txt em $DEST" >&2; exit 1; }

if [ -f "$SUMS" ]; then
  sha256sum -c "$SUMS"
  echo "[ok] arquivos conferem com $SUMS"
else
  sha256sum "${files[@]}" > "$SUMS"
  echo "[novo] $SUMS criado. Faca commit dele para fixar a versao do dataset."
fi

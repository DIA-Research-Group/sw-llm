# Datasets externos

Os arquivos de dados nao sao versionados (licencas e tamanho). Coloque-os aqui.

## CSIC 2010 HTTP (#16)

Requisicoes HTTP rotuladas (normal / anomala: SQLi, XSS, CRLF, buffer overflow,
parameter tampering...). Usado pelo cenario `csic`, que reenvia as requisicoes
pelo proxy real para que o Nginx gere `request_time`, `status` e
`body_bytes_sent` (ausentes no dataset).

Download (Kaggle, requer conta e `~/.kaggle/kaggle.json`):

```bash
pip install kaggle
kaggle datasets download -d ispangler/csic-2010-web-application-attacks -p datasets/csic2010 --unzip
```

Resultado esperado: `datasets/csic2010/*.csv` com as colunas `Method`,
`User-Agent`, `URL`, `content` e `classification` (0 = normal, 1 = anomala).
O leitor (`docker/traffic/csic_replay.py`) tambem aceita `label`/`Class`.

## Por que nao CIC-IDS 2017, LogHub ou BCCC

Ver discussao na issue #16: o CIC-IDS 2017 contem fluxos de rede (nao logs de
aplicacao), o que deixaria o LLM sem conteudo semantico a interpretar; o
LogHub nao tem rotulos de intrusao; os BCCC focam malware/memoria.

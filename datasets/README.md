# Datasets externos

Os arquivos de dados nao sao versionados (licencas e tamanho). Coloque-os aqui.

## CSIC 2010 HTTP (#16)

Requisicoes HTTP rotuladas (normal / anomala: SQLi, XSS, CRLF, buffer overflow,
parameter tampering...). Usado pelo cenario `csic`, que reenvia as requisicoes
pelo proxy real para que o Nginx gere `request_time`, `status` e
`body_bytes_sent` (ausentes no dataset).

Download e verificacao (recomendado):

```bash
datasets/fetch_csic.sh                    # via Kaggle CLI (precisa de ~/.kaggle/kaggle.json)
datasets/fetch_csic.sh /caminho/arquivos  # ou a partir de arquivos ja baixados
```

Na primeira execucao o script grava `datasets/csic2010.sha256` (versione esse
arquivo); nas seguintes confere os arquivos e falha se algo divergir. Cada
execucao do cenario `csic` registra o SHA-256 dos arquivos usados em
`run.json` (`datasets`), e o runner se recusa a rodar sem o dataset.

Formatos aceitos pelo leitor (`docker/traffic/csic_replay.py`):

* CSV do Kaggle, com as colunas `Method`, `User-Agent`, `URL`, `content` e
  `classification` (0 = normal, 1 = anomala); tambem aceita `label`/`Class`;
* `.txt` originais (`normalTrafficTraining.txt`, `normalTrafficTest.txt`,
  `anomalousTrafficTest.txt`): requisicoes HTTP cruas, rotulo inferido pelo
  nome do arquivo (`anomalous` = ataque).

## Por que nao CIC-IDS 2017, LogHub ou BCCC

Ver discussao na issue #16: o CIC-IDS 2017 contem fluxos de rede (nao logs de
aplicacao), o que deixaria o LLM sem conteudo semantico a interpretar; o
LogHub nao tem rotulos de intrusao; os BCCC focam malware/memoria.

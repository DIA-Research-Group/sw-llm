# Relatório do experimento

Média [IC 95%] por configuração; comparações com teste t (Welch, ou pareado no replay) e correção de Holm-Bonferroni.

## Cenário `slowloris`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 | cpu_total_mean |
|---|---|---|---|---|---|---|---|---|
| baseline | 1 | 1.92e+05 | 43 | 75.7 | 1 | 1 | 0.84 | 25.8 |
| +shadow | 1 | 2.58e+04 | 9 | 70.3 | 1 | 3 | 0.848 | 24.5 |

## Cenário `vulhub`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 | cpu_total_mean |
|---|---|---|---|---|---|---|---|---|
| baseline | 1 | 2.13e+05 | 43 | 5.67 | 1 | 1 | 0.379 | 25.9 |
| +shadow | 1 | 4.06e+04 | 19 | 11.1 | 1 | 3 | 0.359 | 24.3 |

## Cenário `zap`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 | cpu_total_mean |
|---|---|---|---|---|---|---|---|---|
| baseline | 1 | 2.88e+05 | 40 | 15.6 | 1 | 2 | 0.869 | 34.5 |
| +shadow | 1 | 3.42e+04 | 9 | 22.9 | 1 | 3 | 0.701 | 29.1 |

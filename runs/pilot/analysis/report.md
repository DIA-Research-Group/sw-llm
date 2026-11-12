# Relatório do experimento

Média [IC 95%] por configuração; comparações com teste t (Welch, ou pareado no replay) e correção de Holm-Bonferroni.

## Cenário `slowloris`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 | cpu_total_mean |
|---|---|---|---|---|---|---|---|---|
| baseline | 2 | 1.94e+05 [1.76e+05, 2.12e+05] | 43 [43, 43] | 73.3 [43.4, 103] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.837 [0.796, 0.878] | 25.4 [20.2, 30.7] |
| +shadow | 2 | 2.83e+04 [-3.83e+03, 6.05e+04] | 8.5 [2.15, 14.9] | 109 [-386, 605] | 1 [1, 1] | 3 [3, 3] | 0.849 [0.833, 0.866] | 25.4 [13.2, 37.7] |

Diferenças significativas (p_holm < 0,05):

- isolated: `baseline` → `+shadow` | llm_calls: 43 → 8.5 (-80.2%, d=-69.00, p=0.00923) melhora
- isolated: `baseline` → `+shadow` | tokens_total: 1.94e+05 → 2.83e+04 (-85.4%, d=-57.33, p=0.00143) melhora
- isolated: `baseline` → `+shadow` | cost_total: 0.0296 → 0.00434 (-85.3%, d=-58.47, p=0.00131) melhora
- isolated: `baseline` → `+shadow` | logs_to_llm_ratio: 0.321 → 0.0475 (-85.2%, d=-58.90, p=0.0037) melhora
- isolated: `baseline` → `+shadow` | window_f1: 0.171 → 0.367 (+113.9%, d=4.45, p=0.0491) melhora
- isolated: `baseline` → `+shadow` | ip_accuracy: 0.0413 → 0.25 (+505.5%, d=14.63, p=0.0434) melhora
- isolated: `baseline` → `+shadow` | detector_cpu_mean: 1.27 → 1.03 (-19.3%, d=-5.07, p=0.0468) melhora

## Cenário `vulhub`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 | cpu_total_mean |
|---|---|---|---|---|---|---|---|---|
| baseline | 2 | 2.09e+05 [1.61e+05, 2.58e+05] | 43.5 [37.1, 49.9] | 8.56 [-28.1, 45.2] | 1 [1, 1] | 1 [1, 1] | 0.382 [0.346, 0.418] | 26.1 [23.1, 29.1] |
| +shadow | 2 | 2.94e+04 [-1.13e+05, 1.71e+05] | 13.5 [-56.4, 83.4] | 9.81 [-6.9, 26.5] | 1 [1, 1] | 3 [3, 3] | 0.36 [0.341, 0.379] | 25.4 [11.2, 39.5] |

Diferenças significativas (p_holm < 0,05):

- isolated: `baseline` → `+shadow` | tokens_total: 2.09e+05 → 2.94e+04 (-86.0%, d=-15.25, p=0.0237) melhora
- isolated: `baseline` → `+shadow` | cost_total: 0.032 → 0.00456 (-85.7%, d=-15.08, p=0.0253) melhora
- isolated: `baseline` → `+shadow` | logs_to_llm_ratio: 0.977 → 0.136 (-86.1%, d=-15.84, p=0.0256) melhora
- isolated: `baseline` → `+shadow` | window_precision: 0.913 → 0.5 (-45.2%, d=-33.00, p=0.0193) piora
- isolated: `baseline` → `+shadow` | ip_accuracy: 0.837 → 0.5 (-40.3%, d=-27.00, p=0.0236) piora
- isolated: `baseline` → `+shadow` | attack_block_rate: 0.664 → 0 (-100.0%, d=-251.80, p=0.00253) piora
- isolated: `baseline` → `+shadow` | benign_block_rate: 0.323 → 0 (-100.0%, d=-19.24, p=0.0331) melhora
- isolated: `baseline` → `+shadow` | iforest_precision: 0.236 → 0.221 (-6.3%, d=-6.72, p=0.0366) piora
- isolated: `baseline` → `+shadow` | iforest_f1: 0.382 → 0.36 (-5.7%, d=-6.74, p=0.0417) piora
- isolated: `baseline` → `+shadow` | detector_cpu_mean: 1.16 → 1.06 (-8.0%, d=-8.77, p=0.0497) melhora
- isolated: `baseline` → `+shadow` | detector_mem_max_mb: 114 → 113 (-0.3%, d=-5.22, p=0.0363) melhora

## Cenário `zap`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 | cpu_total_mean |
|---|---|---|---|---|---|---|---|---|
| baseline | 2 | 2.87e+05 [2.7e+05, 3.04e+05] | 40 [40, 40] | 18.3 [-16.2, 52.8] | 1 [1, 1] | 2 [2, 2] | 0.871 [0.85, 0.892] | 33 [14, 52] |
| +shadow | 2 | 3.43e+04 [3.27e+04, 3.59e+04] | 9 [9, 9] | 20 [-17.1, 57.1] | 1 [1, 1] | 3 [3, 3] | 0.715 [0.536, 0.893] | 30.5 [13, 48] |

Diferenças significativas (p_holm < 0,05):

- isolated: `baseline` → `+shadow` | tokens_total: 2.87e+05 → 3.43e+04 (-88.1%, d=-186.66, p=0.00311) melhora
- isolated: `baseline` → `+shadow` | cost_total: 0.0436 → 0.00525 (-88.0%, d=-181.43, p=0.00306) melhora
- isolated: `baseline` → `+shadow` | logs_to_llm_ratio: 0.363 → 0.0772 (-78.7%, d=-56.29, p=0.000398) melhora
- isolated: `baseline` → `+shadow` | window_precision: 0.803 → 0.25 (-68.9%, d=-69.37, p=0.00918) piora
- isolated: `baseline` → `+shadow` | window_recall: 0.984 → 0.5 (-49.2%, d=-30.00, p=0.0212) piora
- isolated: `baseline` → `+shadow` | window_f1: 0.884 → 0.333 (-62.3%, d=-327.67, p=0.00194) piora
- isolated: `baseline` → `+shadow` | ip_accuracy: 0.698 → 0.25 (-64.2%, d=-86.10, p=0.00739) piora
- isolated: `baseline` → `+shadow` | attack_block_rate: 0.974 → 0.0184 (-98.1%, d=-742.74, p=4.58e-05) piora
- isolated: `baseline` → `+shadow` | benign_block_rate: 0.634 → 0 (-100.0%, d=-789.19, p=0.000807) melhora
- isolated: `baseline` → `+shadow` | iforest_recall: 0.999 → 0.892 (-10.7%, d=-63.11, p=0.00634) piora
- isolated: `baseline` → `+shadow` | iforest_fpr: 0.964 → 0.905 (-6.1%, d=-12.74, p=0.0119) melhora
- isolated: `baseline` → `+shadow` | iforest_auc_roc: 0.352 → 0.435 (+23.7%, d=40.84, p=0.00195) melhora
- isolated: `baseline` → `+shadow` | layer1_recall: 0.999 → 0.892 (-10.7%, d=-63.11, p=0.00634) piora
- isolated: `baseline` → `+shadow` | layer1_fpr: 0.964 → 0.905 (-6.1%, d=-12.74, p=0.0119) melhora
- isolated: `baseline` → `+shadow` | detector_mem_max_mb: 116 → 114 (-1.9%, d=-15.54, p=0.00933) melhora

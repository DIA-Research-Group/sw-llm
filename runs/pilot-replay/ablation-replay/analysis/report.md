# Relatório do experimento

Média [IC 95%] por configuração; comparações com teste t (Welch, ou pareado no replay) e correção de Holm-Bonferroni.

## Cenário `slowloris`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 |
|---|---|---|---|---|---|---|---|
| baseline | 2 | 1.82e+05 [1.47e+05, 2.16e+05] | 46.5 [40.1, 52.9] | 107 [-372, 585] | 1 [1, 1] | 2 [2, 2] | 0.843 [0.83, 0.856] |
| +shadow | 2 | 3.94e+04 [1.83e+03, 7.69e+04] | 13 [13, 13] | 105 [-398, 609] | 1 [1, 1] | 3 [3, 3] | 0.849 [0.833, 0.866] |
| +l1fit | 2 | 5.78e+04 [-2.75e+04, 1.43e+05] | 16 [-22.1, 54.1] | 66.4 [55.5, 77.4] | 1 [1, 1] | 2 [2, 2] | 0.496 |
| +explain | 2 | 1.88e+05 [1.75e+05, 2e+05] | 42.5 [36.1, 48.9] | 68.3 [60, 76.6] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.845 [0.833, 0.857] |
| +richlog | 2 | 2.27e+05 [1.88e+05, 2.66e+05] | 46.5 [40.1, 52.9] | 69.1 | 0.5 [-5.85, 6.85] | 1 [1, 1] | 0.845 [0.828, 0.861] |
| +conn | 2 | 1.87e+05 [1.45e+05, 2.28e+05] | 47.5 [41.1, 53.9] | 61.6 [-14, 137] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.844 [0.838, 0.849] |
| +kg | 2 | 1.72e+05 [1.26e+05, 2.18e+05] | 46 [33.3, 58.7] | 73.7 [-12.8, 160] | 1 [1, 1] | 3 [3, 3] | 0.835 [0.818, 0.852] |
| +kg+kgsafe | 2 | 1.85e+05 [1.84e+05, 1.86e+05] | 47.5 [41.1, 53.9] | 66.4 [50.2, 82.6] | 1 [1, 1] | 2 [2, 2] | 0.844 [0.818, 0.869] |
| +gnn | 2 | 1.84e+05 [1.73e+05, 1.94e+05] | 46.5 [40.1, 52.9] | 106 [-392, 604] | 1 [1, 1] | 2 [2, 2] | 0.842 [0.841, 0.844] |
| +shadow+l1fit | 2 | 3.24e+04 [-5.75e+04, 1.22e+05] | 12 [-13.4, 37.4] | 66.2 [60.1, 72.3] | 1 [1, 1] | 2 [2, 2] | 0.99 |
| +shadow+l1fit+explain | 2 | 6.06e+04 [-1.24e+03, 1.22e+05] | 18 [5.29, 30.7] | 106 [-410, 621] | 1 [1, 1] | 1 [-11.7, 13.7] | 0.991 |
| +shadow+l1fit+explain+richlog | 2 | 5.41e+04 [-2.46e+05, 3.54e+05] | 12.5 [-57.4, 82.4] | 68 [60.1, 76] | 1 [1, 1] | 1.5 [-17.6, 20.6] | 0.99 |
| +shadow+l1fit+explain+richlog+conn | 2 | 4.79e+04 [3.05e+04, 6.53e+04] | 14 [1.29, 26.7] | 16.1 [-6.69, 38.9] | 1 [1, 1] | 1 [1, 1] | 0.991 |
| +shadow+l1fit+explain+richlog+conn+kg | 2 | 3.68e+04 [-2.72e+05, 3.46e+05] | 10 [-66.2, 86.2] | 8.73 [2.9, 14.6] | 1 [1, 1] | 1.5 [-17.6, 20.6] | 0.991 |
| all-gnn | 2 | 3.7e+04 [-5.59e+04, 1.3e+05] | 13 [-12.4, 38.4] | 7.66 [5.93, 9.39] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.99 |
| all | 2 | 5.85e+04 [5.52e+04, 6.17e+04] | 30 [17.3, 42.7] | 18.1 [-40.3, 76.5] | 1 [1, 1] | 3 [3, 3] | 0.991 |
| all-shadow | 2 | 2.19e+05 [1.77e+05, 2.6e+05] | 38.5 [32.1, 44.9] | 26.4 [-112, 165] | 1 [1, 1] | 1.5 [-4.85, 7.85] | — |
| all-l1fit | 2 | 1.19e+05 [-1.64e+05, 4.03e+05] | 40.5 [34.1, 46.9] | 24.5 [23.5, 25.5] | 1 [1, 1] | 2 [2, 2] | 0.849 [0.833, 0.866] |
| all-explain | 2 | 4.11e+04 [-2.7e+05, 3.52e+05] | 14 [-49.5, 77.5] | 13.6 [-75.4, 103] | 1 [1, 1] | 3 [3, 3] | 0.991 |
| all-richlog | 2 | 4.61e+04 [-1.36e+05, 2.28e+05] | 26 [-101, 153] | 25 [-50.6, 101] | 1 [1, 1] | 3 [3, 3] | 0.991 |
| all-conn | 2 | 1.1e+05 [4.61e+04, 1.74e+05] | 32.5 [26.1, 38.9] | 44 [-254, 342] | 1 [1, 1] | 2.5 [-3.85, 8.85] | 0.991 |
| all-kgsafe | 2 | 3.71e+04 [-3.07e+04, 1.05e+05] | 17 [-71.9, 106] | 20 [-136, 176] | 1 [1, 1] | 3 [3, 3] | 0.991 |
| llm_only | 2 | 4.89e+04 [-4.04e+04, 1.38e+05] | 25.5 [-31.7, 82.7] | 68 [47.5, 88.4] | 1 [1, 1] | 3 [3, 3] | — |

Diferenças significativas (p_holm < 0,05):

- isolated: `baseline` → `+l1fit` | iforest_fpr: 0.933 → 0.0296 (-96.8%, d=-109.03, p=0.0289) melhora
- isolated: `baseline` → `+l1fit` | layer1_fpr: 0.933 → 0.0296 (-96.8%, d=-109.03, p=0.0289) melhora
- isolated: `baseline` → `+shadow` | llm_calls: 46.5 → 13 (-72.0%, d=-47.38, p=0.038) melhora
- vs_baseline: `baseline` → `+shadow+l1fit` | iforest_fpr: 0.933 → 0.0462 (-95.0%, d=-1706.00, p=0.00369) melhora
- vs_baseline: `baseline` → `+shadow+l1fit` | layer1_fpr: 0.933 → 0.0462 (-95.0%, d=-1706.00, p=0.00369) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | iforest_fpr: 0.933 → 0.0453 (-95.1%, d=-487.05, p=0.00924) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | layer1_fpr: 0.933 → 0.0453 (-95.1%, d=-487.05, p=0.00924) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | iforest_fpr: 0.933 → 0.0462 (-95.0%, d=-1706.00, p=0.00369) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | layer1_fpr: 0.933 → 0.0462 (-95.0%, d=-1706.00, p=0.00369) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | iforest_fpr: 0.933 → 0.0429 (-95.4%, d=-768.22, p=0.00645) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | layer1_fpr: 0.933 → 0.0429 (-95.4%, d=-768.22, p=0.00645) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn+kg` | iforest_fpr: 0.933 → 0.0448 (-95.2%, d=-358.99, p=0.01) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn+kg` | layer1_fpr: 0.933 → 0.0448 (-95.2%, d=-358.99, p=0.0113) melhora
- vs_baseline: `baseline` → `all` | iforest_fpr: 0.933 → 0.0443 (-95.2%, d=-284.32, p=0.0111) melhora
- vs_baseline: `baseline` → `all-conn` | iforest_fpr: 0.933 → 0.0443 (-95.2%, d=-284.32, p=0.0111) melhora
- vs_baseline: `baseline` → `all-explain` | iforest_fpr: 0.933 → 0.0453 (-95.1%, d=-487.05, p=0.00924) melhora
- vs_baseline: `baseline` → `all-gnn` | iforest_fpr: 0.933 → 0.0462 (-95.0%, d=-1706.00, p=0.00369) melhora
- vs_baseline: `baseline` → `all-gnn` | layer1_fpr: 0.933 → 0.0462 (-95.0%, d=-1706.00, p=0.00369) melhora
- vs_baseline: `baseline` → `all-kgsafe` | iforest_fpr: 0.933 → 0.0443 (-95.2%, d=-284.32, p=0.0111) melhora
- vs_baseline: `baseline` → `all-richlog` | iforest_fpr: 0.933 → 0.0443 (-95.2%, d=-284.32, p=0.0111) melhora
- vs_baseline: `baseline` → `all-shadow` | iforest_precision: 0.729 → 0 (-100.0%, d=-337.08, p=0.0187) piora
- vs_baseline: `baseline` → `all-shadow` | iforest_fpr: 0.933 → 0.0383 (-95.9%, d=-176.85, p=0.0111) melhora
- cumulative: `+shadow` → `+shadow+l1fit` | iforest_fpr: 0.89 → 0.0462 (-94.8%, d=-253.66, p=0.0124) melhora
- cumulative: `+shadow` → `+shadow+l1fit` | layer1_fpr: 0.89 → 0.0462 (-94.8%, d=-253.66, p=0.0124) melhora
- loo: `all-l1fit` → `all` | iforest_fpr: 0.89 → 0.0443 (-95.0%, d=-142.59, p=0.0126) melhora
- refinement: `+kg` → `+kg+kgsafe` | latency_p95: 2.51 → 3.3 (+31.4%, d=38.45, p=0.0117) piora
- refinement: `+kg` → `+kg+kgsafe` | benign_block_rate: 0.896 → 0.368 (-58.9%, d=-10.67, p=0.0421) melhora
- refinement: `+kg` → `+kg+kgsafe` | iforest_f1: 0.835 → 0.844 (+1.0%, d=9.02, p=0.0498) melhora
- arm: `baseline` → `llm_only` | tokens_total: 1.82e+05 → 4.89e+04 (-73.1%, d=-21.85, p=0.0206) melhora
- arm: `baseline` → `llm_only` | cost_total: 0.0278 → 0.00759 (-72.7%, d=-21.01, p=0.0214) melhora
- arm: `baseline` → `llm_only` | logs_to_llm_ratio: 0.302 → 0.0845 (-72.1%, d=-22.61, p=0.0199) melhora
- arm: `baseline` → `llm_only` | benign_block_rate: 0.417 → 0 (-100.0%, d=-58.43, p=0.0077) melhora
- arm: `baseline` → `llm_only` | layer1_fpr: 0.933 → 0 (-100.0%, d=-220.58, p=0.00204) melhora

## Cenário `vulhub`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 |
|---|---|---|---|---|---|---|---|
| baseline | 2 | 2.08e+05 [2.05e+05, 2.11e+05] | 46.5 [40.1, 52.9] | 7.53 [-27.1, 42.2] | 1 [1, 1] | 1 [1, 1] | 0.364 [0.347, 0.38] |
| +shadow | 2 | 3.18e+04 [-1.3e+05, 1.94e+05] | 16.5 [-66.1, 99.1] | 6.09 [-19.9, 32.1] | 1 [1, 1] | 3 [3, 3] | 0.36 [0.341, 0.379] |
| +l1fit | 2 | 3.29e+04 [-9.85e+03, 7.57e+04] | 13.5 [-18.3, 45.3] | 57 [-384, 498] | 0.833 [-1.28, 2.95] | 1.5 [-4.85, 7.85] | 0.0481 [-0.327, 0.423] |
| +explain | 2 | 2.07e+05 [2.06e+05, 2.09e+05] | 38 [38, 38] | 18.7 [-22.8, 60.2] | 1 [1, 1] | 0.5 [-5.85, 6.85] | 0.366 [0.329, 0.404] |
| +richlog | 2 | 2.61e+05 [2.49e+05, 2.73e+05] | 47 [34.3, 59.7] | 6.7 [-32.9, 46.3] | 1 [1, 1] | 1 [1, 1] | 0.363 [0.353, 0.373] |
| +conn | 2 | 2.07e+05 [2e+05, 2.15e+05] | 46.5 [40.1, 52.9] | 8.92 [-10.7, 28.6] | 1 [1, 1] | 1 [1, 1] | 0.363 [0.344, 0.383] |
| +kg | 2 | 1.93e+05 [1.86e+05, 2e+05] | 46 [33.3, 58.7] | 13.8 [-60.9, 88.5] | 1 [1, 1] | 3 [3, 3] | 0.349 [0.323, 0.376] |
| +kg+kgsafe | 2 | 1.93e+05 [1.81e+05, 2.05e+05] | 46 [46, 46] | 9.85 [6.12, 13.6] | 1 [1, 1] | 3 [3, 3] | 0.361 [0.351, 0.371] |
| +gnn | 2 | 2.07e+05 [2e+05, 2.14e+05] | 47 [47, 47] | 10.6 [5.1, 16.2] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.36 [0.331, 0.389] |
| +shadow+l1fit | 2 | 2.03e+04 [-1.14e+04, 5.21e+04] | 10 [10, 10] | 27.4 [-52.5, 107] | 0.833 [-1.28, 2.95] | 1.5 [-4.85, 7.85] | 0.18 [-1.08, 1.44] |
| +shadow+l1fit+explain | 2 | 2.55e+04 [8.03e+03, 4.29e+04] | 9.5 [3.15, 15.9] | 29.2 [-42.9, 101] | 0.833 [-1.28, 2.95] | 1 [1, 1] | 0.184 [-1.13, 1.5] |
| +shadow+l1fit+explain+richlog | 2 | 3.28e+04 [5.1e+03, 6.05e+04] | 10 [10, 10] | 24.2 [-12.5, 61] | 1 [1, 1] | 0.5 [-5.85, 6.85] | 0.2 [-0.973, 1.37] |
| +shadow+l1fit+explain+richlog+conn | 2 | 3.44e+04 [8e+03, 6.07e+04] | 9.5 [-9.56, 28.6] | 24.7 [-10.9, 60.4] | 0.833 [-1.28, 2.95] | 0.5 [-5.85, 6.85] | 0.192 [-1.08, 1.47] |
| +shadow+l1fit+explain+richlog+conn+kg | 2 | 2.94e+04 [5.76e+03, 5.3e+04] | 8.5 [2.15, 14.9] | 17.1 [-57.9, 92] | 1 [1, 1] | 1 [1, 1] | 0.186 [-1.16, 1.53] |
| all-gnn | 2 | 3.97e+04 [1.41e+04, 6.52e+04] | 10.5 [-8.56, 29.6] | 16.4 [-40.7, 73.6] | 1 [1, 1] | 0 [0, 0] | 0.184 [-1.13, 1.5] |
| all | 2 | 7.43e+04 [4.79e+04, 1.01e+05] | 30.5 [-26.7, 87.7] | 7 [-4.64, 18.6] | 1 [1, 1] | 2.5 [-3.85, 8.85] | 0.184 [-1.13, 1.5] |
| all-shadow | 2 | 2.44e+05 [1.63e+05, 3.25e+05] | 37.5 [18.4, 56.6] | 8.22 [-47.7, 64.1] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.0122 [-0.0657, 0.0902] |
| all-l1fit | 2 | 1.14e+05 [-6.52e+05, 8.8e+05] | 28.5 [-130, 187] | 10.9 [-13.9, 35.6] | 1 [1, 1] | 2.5 [-3.85, 8.85] | 0.36 [0.341, 0.379] |
| all-explain | 2 | 3.82e+04 [-9.92e+04, 1.76e+05] | 16 [-34.8, 66.8] | 7.03 [-23.2, 37.3] | 1 [1, 1] | 3 [3, 3] | 0.186 [-1.16, 1.53] |
| all-richlog | 2 | 1.02e+05 [9.25e+04, 1.12e+05] | 37.5 [31.1, 43.9] | 9.81 [1.29, 18.3] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.184 [-1.13, 1.5] |
| all-conn | 2 | 1.2e+05 [-1.12e+05, 3.52e+05] | 35 [-3.12, 73.1] | 8.94 [-1.15, 19] | 1 [1, 1] | 2 [-10.7, 14.7] | 0.191 [-1.04, 1.43] |
| all-kgsafe | 2 | 2.94e+04 [-1.34e+05, 1.93e+05] | 10.5 [-34, 55] | 8.57 [0.233, 16.9] | 1 [1, 1] | 3 [3, 3] | 0.188 [-0.971, 1.35] |
| llm_only | 2 | 3.45e+04 [4.66e+03, 6.44e+04] | 21.5 [2.44, 40.6] | 2.31 [-11.7, 16.3] | 1 [1, 1] | 3 [3, 3] | — |

Diferenças significativas (p_holm < 0,05):

- isolated: `baseline` → `+gnn` | layer1_fpr: 0.936 → 0.976 (+4.3%, d=64.10, p=0.0351) piora
- isolated: `baseline` → `+l1fit` | cost_total: 0.0316 → 0.0051 (-83.9%, d=-55.91, p=0.0483) melhora
- isolated: `baseline` → `+l1fit` | iforest_recall: 1 → 0.0279 (-97.2%, d=-39.12, p=0.0345) piora
- isolated: `baseline` → `+l1fit` | iforest_fpr: 0.936 → 0.0306 (-96.7%, d=-124.53, p=0.0217) melhora
- isolated: `baseline` → `+l1fit` | iforest_auc_roc: 0.51 → 0.42 (-17.6%, d=-158.68, p=0.0199) piora
- isolated: `baseline` → `+l1fit` | layer1_recall: 1 → 0.0279 (-97.2%, d=-39.12, p=0.0345) piora
- isolated: `baseline` → `+l1fit` | layer1_fpr: 0.936 → 0.0306 (-96.7%, d=-124.53, p=0.0217) melhora
- isolated: `baseline` → `+richlog` | cost_total: 0.0316 → 0.0398 (+25.8%, d=80.42, p=0.0392) piora
- isolated: `baseline` → `+shadow` | iforest_recall: 1 → 0.965 (-3.5%, d=-81.60, p=0.0221) piora
- isolated: `baseline` → `+shadow` | layer1_recall: 1 → 0.965 (-3.5%, d=-81.60, p=0.0221) piora
- isolated: `baseline` → `+shadow` | layer1_fpr: 0.936 → 0.907 (-3.0%, d=-44.39, p=0.0406) melhora
- vs_baseline: `baseline` → `+shadow+l1fit` | iforest_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.036) melhora
- vs_baseline: `baseline` → `+shadow+l1fit` | layer1_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.0421) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | cost_total: 0.0316 → 0.00433 (-86.3%, d=-438.95, p=0.0133) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | logs_to_llm_ratio: 0.996 → 0.11 (-89.0%, d=-161.26, p=0.0391) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | iforest_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.036) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | layer1_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.0421) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | iforest_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.036) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | iforest_auc_roc: 0.51 → 0.816 (+60.1%, d=359.12, p=0.0175) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | layer1_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.0421) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | iforest_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.036) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | layer1_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.0421) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn+kg` | iforest_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.036) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn+kg` | layer1_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.0421) melhora
- vs_baseline: `baseline` → `all` | iforest_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.036) melhora
- vs_baseline: `baseline` → `all-conn` | iforest_fpr: 0.936 → 0.038 (-95.9%, d=-80.13, p=0.036) melhora
- vs_baseline: `baseline` → `all-explain` | iforest_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.036) melhora
- vs_baseline: `baseline` → `all-gnn` | cost_total: 0.0316 → 0.00588 (-81.4%, d=-1585.90, p=0.00397) melhora
- vs_baseline: `baseline` → `all-gnn` | iforest_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.036) melhora
- vs_baseline: `baseline` → `all-gnn` | layer1_fpr: 0.936 → 0.0412 (-95.6%, d=-135.12, p=0.0421) melhora
- vs_baseline: `baseline` → `all-kgsafe` | iforest_fpr: 0.936 → 0.0421 (-95.5%, d=-168.26, p=0.0348) melhora
- vs_baseline: `baseline` → `all-kgsafe` | iforest_auc_roc: 0.51 → 0.813 (+59.5%, d=277.11, p=0.0211) melhora
- vs_baseline: `baseline` → `all-l1fit` | iforest_fpr: 0.936 → 0.907 (-3.0%, d=-44.39, p=0.036) melhora
- vs_baseline: `baseline` → `all-richlog` | iforest_fpr: 0.936 → 0.0417 (-95.5%, d=-149.87, p=0.036) melhora
- vs_baseline: `baseline` → `all-shadow` | latency_mean: 1.87 → 3.7 (+98.4%, d=234.40, p=0.0269) piora
- vs_baseline: `baseline` → `all-shadow` | iforest_recall: 1 → 0.00696 (-99.3%, d=-199.11, p=0.0294) piora
- vs_baseline: `baseline` → `all-shadow` | iforest_fpr: 0.936 → 0.0347 (-96.3%, d=-225.49, p=0.0279) melhora
- cumulative: `+shadow` → `+shadow+l1fit` | iforest_fpr: 0.907 → 0.0412 (-95.5%, d=-144.77, p=0.0124) melhora
- cumulative: `+shadow` → `+shadow+l1fit` | layer1_fpr: 0.907 → 0.0412 (-95.5%, d=-144.77, p=0.0124) melhora
- loo: `all-shadow` → `all` | attack_block_rate: 0.901 → 0 (-100.0%, d=-81.60, p=0.00552) piora
- loo: `all-l1fit` → `all` | iforest_fpr: 0.907 → 0.0417 (-95.4%, d=-162.47, p=0.0166) melhora
- loo: `all-explain` → `all` | iforest_precision: 0.399 → 0.395 (-1.1%, d=-3787.97, p=0.000713) piora
- loo: `all-richlog` → `all` | cost_total: 0.0173 → 0.0126 (-26.8%, d=-1181.08, p=0.00267) melhora
- refinement: `+kg` → `+kg+kgsafe` | benign_block_rate: 0.923 → 0.414 (-55.1%, d=-91.25, p=0.00493) melhora
- arm: `baseline` → `llm_only` | tokens_total: 2.08e+05 → 3.45e+04 (-83.4%, d=-47.75, p=0.00943) melhora
- arm: `baseline` → `llm_only` | cost_total: 0.0316 → 0.0054 (-82.9%, d=-32.68, p=0.0138) melhora
- arm: `baseline` → `llm_only` | logs_to_llm_ratio: 0.996 → 0.167 (-83.2%, d=-42.44, p=0.0106) melhora
- arm: `baseline` → `llm_only` | window_precision: 0.88 → 0.5 (-43.2%, d=-11.86, p=0.0379) piora
- arm: `baseline` → `llm_only` | ip_accuracy: 0.856 → 0.5 (-41.6%, d=-11.25, p=0.04) piora
- arm: `baseline` → `llm_only` | attack_block_rate: 0.929 → 0 (-100.0%, d=-40.50, p=0.0111) piora
- arm: `baseline` → `llm_only` | benign_block_rate: 0.322 → 0 (-100.0%, d=-22.70, p=0.0198) melhora
- arm: `baseline` → `llm_only` | layer1_fpr: 0.936 → 0 (-100.0%, d=-282.04, p=0.0016) melhora

## Cenário `zap`

| config | n | tokens_total | llm_calls | ttm_s | attack_ip_recall | fp_ips | iforest_f1 |
|---|---|---|---|---|---|---|---|
| baseline | 2 | 2.79e+05 [1.79e+05, 3.79e+05] | 45.5 [39.1, 51.9] | 19.7 [-31.3, 70.7] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.762 [0.57, 0.953] |
| +shadow | 2 | 2.31e+04 [1.33e+03, 4.48e+04] | 7.5 [1.15, 13.9] | 16.1 [5.83, 26.4] | 1 [1, 1] | 3 [3, 3] | 0.715 [0.536, 0.893] |
| +l1fit | 2 | 1.46e+05 [-4.3e+04, 3.36e+05] | 25.5 [6.44, 44.6] | 22.8 [-56, 102] | 1 [1, 1] | 1 [1, 1] | 0.0473 |
| +explain | 2 | 2.57e+05 [1.07e+05, 4.08e+05] | 39 [26.3, 51.7] | 26.9 [-123, 177] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.755 [0.634, 0.876] |
| +richlog | 2 | 3.45e+05 [2.79e+05, 4.12e+05] | 45.5 [39.1, 51.9] | 18.3 [-69.4, 106] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.759 [0.608, 0.911] |
| +conn | 2 | 2.82e+05 [1.65e+05, 3.99e+05] | 47 [34.3, 59.7] | 25.3 [-86.3, 137] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.759 [0.532, 0.986] |
| +kg | 2 | 2.79e+05 [2.6e+05, 2.97e+05] | 45.5 [26.4, 64.6] | 37.1 [-54.8, 129] | 1 [1, 1] | 3 [3, 3] | 0.747 [0.589, 0.904] |
| +kg+kgsafe | 2 | 2.87e+05 [1.52e+05, 4.22e+05] | 46.5 [40.1, 52.9] | 21.6 [-98.4, 142] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.759 [0.528, 0.991] |
| +gnn | 2 | 2.81e+05 [2.11e+05, 3.52e+05] | 46 [33.3, 58.7] | 21.9 [-64.6, 108] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.758 [0.549, 0.967] |
| +shadow+l1fit | 2 | 3.4e+04 [-1.05e+05, 1.73e+05] | 10.5 [-46.7, 67.7] | 16.6 [13.5, 19.7] | 1 [1, 1] | 2.5 [-3.85, 8.85] | 0.0669 [-0.368, 0.502] |
| +shadow+l1fit+explain | 2 | 5.6e+04 [-3.55e+04, 1.47e+05] | 16.5 [-2.56, 35.6] | 16.8 [13.3, 20.2] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.0632 [-0.42, 0.546] |
| +shadow+l1fit+explain+richlog | 2 | 7.63e+04 [7.3e+04, 7.95e+04] | 17.5 [11.1, 23.9] | 27.9 [-105, 161] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.0691 [-0.338, 0.477] |
| +shadow+l1fit+explain+richlog+conn | 2 | 6.88e+04 [1.82e+04, 1.19e+05] | 18.5 [-0.559, 37.6] | 19.9 [-9.43, 49.3] | 1 [1, 1] | 1 [1, 1] | 0.0632 [-0.42, 0.546] |
| +shadow+l1fit+explain+richlog+conn+kg | 2 | 4.89e+04 [-1.29e+05, 2.27e+05] | 10.5 [-59.4, 80.4] | 28.8 [-44, 102] | 1 [1, 1] | 2 [-10.7, 14.7] | 0.0632 [-0.42, 0.546] |
| all-gnn | 2 | 8.91e+04 [5.37e+03, 1.73e+05] | 21.5 [2.44, 40.6] | 18 [16.6, 19.4] | 1 [1, 1] | 0 [0, 0] | 0.0632 [-0.42, 0.546] |
| all | 2 | 1.78e+05 [-2.15e+05, 5.7e+05] | 38.5 [19.4, 57.6] | 17.9 [-61.5, 97.4] | 1 [1, 1] | 1.5 [-4.85, 7.85] | 0.0632 [-0.42, 0.546] |
| all-shadow | 2 | 3.03e+05 [2.77e+05, 3.28e+05] | 35.5 [29.1, 41.9] | 21.3 [-69.9, 112] | 1 [1, 1] | 1 [1, 1] | 0.047 |
| all-l1fit | 2 | 1.32e+05 [-3.94e+05, 6.57e+05] | 37.5 [18.4, 56.6] | 33.8 [-87.5, 155] | 1 [1, 1] | 2 [-10.7, 14.7] | 0.715 [0.536, 0.893] |
| all-explain | 2 | 8.08e+04 [-5.44e+04, 2.16e+05] | 34 [-54.9, 123] | 14.4 [-1.99, 30.8] | 1 [1, 1] | 2.5 [-3.85, 8.85] | 0.067 [-0.368, 0.502] |
| all-richlog | 2 | 8.94e+04 [-3.53e+04, 2.14e+05] | 36.5 [17.4, 55.6] | 19.3 [-64.3, 103] | 1 [1, 1] | 2 [2, 2] | 0.0631 [-0.419, 0.545] |
| all-conn | 2 | 1.46e+05 [-2.74e+05, 5.65e+05] | 34.5 [28.1, 40.9] | 18.2 [-1.42, 37.7] | 1 [1, 1] | 3 [3, 3] | 0.067 [-0.368, 0.502] |
| all-kgsafe | 2 | 6.35e+04 [-4.46e+05, 5.73e+05] | 14 [-113, 141] | 22.6 [10.3, 34.8] | 1 [1, 1] | 3 [3, 3] | 0.067 [-0.368, 0.502] |
| llm_only | 2 | 2.56e+04 [2.55e+04, 2.57e+04] | 8 [8, 8] | 17.9 [17.1, 18.6] | 1 [1, 1] | 3 [3, 3] | — |

Diferenças significativas (p_holm < 0,05):

- isolated: `baseline` → `+kg` | benign_block_rate: 0.346 → 0.928 (+168.4%, d=302.50, p=0.0104) piora
- isolated: `baseline` → `+l1fit` | iforest_recall: 0.998 → 0.0125 (-98.8%, d=-51.50, p=0.0437) piora
- isolated: `baseline` → `+l1fit` | iforest_fpr: 0.934 → 0.0449 (-95.2%, d=-865.45, p=0.00364) melhora
- isolated: `baseline` → `+l1fit` | layer1_recall: 0.998 → 0.0125 (-98.8%, d=-51.50, p=0.0437) piora
- isolated: `baseline` → `+l1fit` | layer1_fpr: 0.934 → 0.0449 (-95.2%, d=-865.45, p=0.00364) melhora
- vs_baseline: `baseline` → `+shadow+l1fit` | iforest_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0228) melhora
- vs_baseline: `baseline` → `+shadow+l1fit` | layer1_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0292) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | tokens_total: 2.79e+05 → 5.6e+04 (-80.0%, d=-236.84, p=0.0266) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | cost_total: 0.0424 → 0.00931 (-78.1%, d=-976.42, p=0.00645) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | iforest_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0228) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain` | layer1_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0292) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | iforest_fpr: 0.934 → 0.0561 (-94.0%, d=-236.70, p=0.0228) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog` | layer1_fpr: 0.934 → 0.0561 (-94.0%, d=-236.70, p=0.0266) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | logs_to_llm_ratio: 0.632 → 0.122 (-80.7%, d=-1040.32, p=0.00606) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | iforest_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0228) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn` | layer1_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0292) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn+kg` | iforest_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0228) melhora
- vs_baseline: `baseline` → `+shadow+l1fit+explain+richlog+conn+kg` | layer1_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0292) melhora
- vs_baseline: `baseline` → `all` | iforest_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0228) melhora
- vs_baseline: `baseline` → `all-conn` | iforest_fpr: 0.934 → 0.0561 (-94.0%, d=-236.70, p=0.0228) melhora
- vs_baseline: `baseline` → `all-explain` | iforest_fpr: 0.934 → 0.0561 (-94.0%, d=-236.70, p=0.0228) melhora
- vs_baseline: `baseline` → `all-gnn` | latency_mean: 1.96 → 2.76 (+40.9%, d=228.68, p=0.0256) piora
- vs_baseline: `baseline` → `all-gnn` | iforest_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0228) melhora
- vs_baseline: `baseline` → `all-gnn` | layer1_fpr: 0.934 → 0.0566 (-93.9%, d=-200.72, p=0.0292) melhora
- vs_baseline: `baseline` → `all-kgsafe` | iforest_fpr: 0.934 → 0.0561 (-94.0%, d=-236.70, p=0.0228) melhora
- vs_baseline: `baseline` → `all-richlog` | iforest_fpr: 0.934 → 0.0575 (-93.8%, d=-287.15, p=0.0204) melhora
- vs_baseline: `baseline` → `all-shadow` | latency_mean: 1.96 → 4.16 (+111.8%, d=503.41, p=0.0125) piora
- vs_baseline: `baseline` → `all-shadow` | latency_p95: 4.24 → 8.4 (+98.2%, d=318.14, p=0.0198) piora
- vs_baseline: `baseline` → `all-shadow` | iforest_fpr: 0.934 → 0.05 (-94.6%, d=-390.94, p=0.0161) melhora
- cumulative: `+shadow` → `+shadow+l1fit` | iforest_fpr: 0.905 → 0.0566 (-93.7%, d=-72.22, p=0.0187) melhora
- cumulative: `+shadow` → `+shadow+l1fit` | layer1_fpr: 0.905 → 0.0566 (-93.7%, d=-72.22, p=0.0249) melhora
- cumulative: `+shadow+l1fit+explain+richlog+conn+kg` → `all-gnn` | window_f1: 0.5 → 0.833 (+66.7%, d=6004799503160662.00, p=5.25e-16) melhora
- loo: `all-shadow` → `all` | window_f1: 0.893 → 0.4 (-55.2%, d=-917.97, p=0.00294) piora
- loo: `all-shadow` → `all` | attack_block_rate: 0.921 → 0.0184 (-98.0%, d=-20.55, p=0.0219) piora
- loo: `all-l1fit` → `all` | iforest_fpr: 0.905 → 0.0566 (-93.7%, d=-72.22, p=0.0374) melhora
- loo: `all-gnn` → `all` | layer1_recall: 0.0343 → 1 (+2818.0%, d=32.91, p=0.041) melhora
- arm: `baseline` → `llm_only` | llm_calls: 45.5 → 8 (-82.4%, d=-53.03, p=0.00849) melhora
- arm: `baseline` → `llm_only` | tokens_total: 2.79e+05 → 2.56e+04 (-90.8%, d=-22.77, p=0.0198) melhora
- arm: `baseline` → `llm_only` | cost_total: 0.0424 → 0.00393 (-90.7%, d=-23.29, p=0.0193) melhora
- arm: `baseline` → `llm_only` | logs_to_llm_ratio: 0.632 → 0.0605 (-90.4%, d=-43.82, p=0.0103) melhora
- arm: `baseline` → `llm_only` | window_precision: 0.811 → 0.25 (-69.2%, d=-23.04, p=0.0195) piora
- arm: `baseline` → `llm_only` | window_recall: 0.836 → 0.5 (-40.2%, d=-13.65, p=0.0329) piora
- arm: `baseline` → `llm_only` | window_f1: 0.823 → 0.333 (-59.5%, d=-20.02, p=0.0225) piora
- arm: `baseline` → `llm_only` | attack_block_rate: 0.927 → 0.0184 (-98.0%, d=-28.58, p=0.0157) piora
- arm: `baseline` → `llm_only` | benign_block_rate: 0.346 → 0 (-100.0%, d=-14.42, p=0.0312) melhora
- arm: `baseline` → `llm_only` | layer1_recall: 0.998 → 0 (-100.0%, d=-665.30, p=0.000677) piora
- arm: `baseline` → `llm_only` | layer1_fpr: 0.934 → 0 (-100.0%, d=-529.06, p=0.000851) melhora

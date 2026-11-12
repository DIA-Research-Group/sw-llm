# Piloto com o modelo real (11–12/11/2026)

Modelo `openai/gpt-4o-mini-2024-07-18` (servido pela OpenAI via OpenRouter),
janela de ataque de 300 s, aquecimento de 60 s, **2 repetições** por célula.
Custo total do piloto: ≈ US$ 3.

| Fase | Experimento | Saída |
|---|---|---|
| Ao vivo | `experiments/pilot.yaml`, `baseline` e `+shadow` em `zap`, `slowloris`, `vulhub` (12 execuções) | `runs/pilot/analysis/` |
| Replay pareado | `experiments/ablation-replay.yaml` (23 configurações) sobre o tráfego gravado em `+shadow` (138 execuções) | `runs/pilot-replay/ablation-replay/analysis/` |

Só `analysis/` e `experiment.yaml` são versionados; os logs brutos
(`logs.jsonl`, `layer1.csv`) ficam fora do git.

**Com n = 2 os resultados são indicativos, não conclusivos.** Os testes
(Welch no ao vivo, t pareado no replay) aparecem nos relatórios, mas com dois
pontos por célula o IC 95% é muito largo e um "p < 0,05" depende de desvios
quase nulos. O piloto serve para validar o pipeline e escolher onde investir
repetições.

## Integridade dos dados

- 1ª tentativa: os créditos acabaram na repetição 2 ao vivo (HTTP 402). Essas
  execuções foram descartadas e refeitas. Desde então 401/402/403 abortam a
  matriz (`LLMAccountError`).
- Replay: a máquina suspendeu durante a noite e a rede caiu por ~2 min no dia
  seguinte. 5 execuções tiveram janelas com erro de rede, foram apagadas e
  refeitas. Desde então falhas de conexão são repetidas até 3 vezes.
- Estado final: 12 execuções ao vivo e 138 de replay, **todas as janelas com
  status `ok`** (3.953 no replay).

## Principais observações

Médias das 2 repetições; números do replay salvo indicação.

1. **Detecção.** Todos os atacantes foram detectados em praticamente todas as
   configurações (`attack_ip_recall` = 1). Exceções: algumas configurações
   com `l1fit` no VulHub (0,83: um dos 3 atacantes escapou em uma repetição)
   e `+richlog` no Slowloris (0,5).
2. **Falsos positivos do LLM são o principal problema.** Quase todas as
   configurações marcam 1–3 dos 3 usuários benignos (`fp_ips`).
3. **`l1fit` (iForest retreinado no aquecimento)** derruba o FPR da camada 1
   de ≈ 0,93 para ≈ 0,03–0,06 nos três cenários e corta 44–71% das chamadas
   ao LLM. Custo: TTM maior no VulHub (7,5 s → 57 s isolado).
4. **`shadow`** reduz tokens em 78–92% (IP já marcado não abre janela),
   confirmado ao vivo (−85% a −88%).
5. **`conn` (telemetria de conexões)** é o que detecta o Slowloris cedo: na
   pilha cumulativa o TTM cai de 68 s para 16 s; `all-conn` vs `all`: 44 s
   vs 18 s.
6. **`gnn`** em OU com o iForest aumenta alarmes. Remover a GNN da pilha
   completa (`all-gnn`) reduz as chamadas ao LLM em 44–66% e, no VulHub e no
   ZAP, zerou os falsos positivos.
7. **`richlog`** aumenta os tokens em ~25%. Sem ganho claro de detecção
   neste piloto (o atacante do traversal já era pego por outros sinais).
8. **`kg`** tomou poucas decisões (1–3 por execução). O atalho permissivo
   marcou os 3 benignos em todos os cenários; `kgsafe` reduziu isso no
   Slowloris e no ZAP, mas não no VulHub.
9. **`explain`** não mostrou efeito consistente em detecção ou falsos
   positivos e custa mais tokens por chamada.
10. **`llm_only`** (sem camada 1, em shadow) ficou barato porque o shadow
    corta as janelas após o primeiro bloqueio, mas marcou os 3 benignos nos
    três cenários.

## Próximos passos sugeridos

- Atacar os falsos positivos do LLM (prompt, contexto por IP, limiar de
  confiança) antes de gastar repetições na matriz completa.
- Repetir o replay com mais repetições gravadas (≥ 10) para os fatores com
  efeito grande (`l1fit`, `shadow`, `conn`, `gnn`).
- Calibrar `kg_similarity_threshold` com `ips.calibrate` (já há repetições
  ímpar/par).

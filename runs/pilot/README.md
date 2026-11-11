# Piloto com o modelo real (2026-11-11)

`experiments/pilot.yaml`, configuracoes `baseline` e `+shadow`, cenarios
`zap`, `slowloris` e `vulhub`, modelo `openai/gpt-4o-mini-2024-07-18`
(servido pela OpenAI via OpenRouter), janela de ataque de 300 s.

Somente a repeticao 1 e valida (n = 1 por celula, sem inferencia
estatistica). Os creditos do provedor acabaram durante a repeticao 2 e as
chamadas passaram a retornar HTTP 402; essas execucoes foram descartadas.
Desde entao, 401/402/403 abortam a execucao (`LLMAccountError`) em vez de
gravar janelas com erro.

Versionado aqui apenas `analysis/` (resumo, comparacoes, relatorio e
figuras). Os logs brutos (`logs.jsonl`, `layer1.csv`) ficam fora do git.

Observacoes:

- todos os atacantes foram detectados (`attack_ip_recall` = 1) nos 6 casos;
- o LLM marcou usuarios benignos: 1-2 IPs no modo active e os 3 no shadow;
- o modo shadow reduziu os tokens em 5-8x (IP ja marcado nao abre janelas);
- o Slowloris so foi detectado apos ~70 s (408 do Nginx), sem telemetria
  de conexoes.

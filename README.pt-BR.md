# Sistema Autonômico de Prevenção de Intrusão via Large Language Models (LLM-IPS)

[English](README.md) | **Português**

Este repositório reúne o ambiente experimental e o código-fonte da pesquisa sobre a integração de Large Language Models (LLMs) em arquiteturas autonômicas de segurança. O projeto avalia a eficácia de LLMs na análise de logs, na classificação de ameaças e na resposta automatizada a incidentes, em um ambiente conteinerizado.

Além do detector híbrido original (Isolation Forest + LLM), o repositório contém um **framework de ablação**: cada melhoria proposta é uma flag independente, que pode ser medida isoladamente, empilhada com as demais ou removida da pilha completa, em execuções repetidas com intervalos de confiança e testes de significância.

## 1. Visão Geral da Pesquisa

O objetivo principal é verificar se LLMs podem ser usados como motor de decisão para identificar e mitigar ataques automaticamente, e quanto um pré-filtro estatístico barato reduz o custo operacional dessa abordagem.

### 1.1 Hipóteses
*   **H1 (Acurácia de detecção):** LLMs distinguem com precisão tráfego legítimo de padrões maliciosos a partir de dados brutos de observabilidade.
*   **H2 (Identificação da entidade):** LLMs extraem corretamente o identificador de origem (ex.: endereço IP) do agente da ameaça a partir de logs estruturados.
*   **H3 (Eficácia da mitigação):** LLMs formulam e executam estratégias de mitigação em nível de rede (ex.: regras dinâmicas de firewall) dentro de uma janela de tempo que minimiza a exposição do sistema.

## 2. Arquitetura Técnica

```
 usuarios benignos ─┐                                   ┌─ Juice Shop (alvo principal)
 atacantes ─────────┼─► Nginx (nginx-proxy, blocklist) ─┼─ [WAF OWASP CRS]  (braco #19)
 (ZAP, Slowloris,   │ log de acesso JSON via syslog     └─ alvos VulHub     (cenario #22)
  VulHub, CSIC)     ▼
               Logstash ──► Elasticsearch  (ou Redis, #21)
                                 │
                                 ▼
        ips.detector ── Camada 1: Isolation Forest (+ GNN, #13) ──┐
                     ── telemetria de conexoes (#17)               ├─► janela (5 s) ─► Camada 2: LLM
                     ── knowledge graph / Neo4j (#13) ─────────────┘         │
                                                                             ▼
                                   mitigacao: bloqueio | registro shadow | bloqueio com TTL (#18)
```

*   **Aplicação-alvo:** OWASP Juice Shop; sistema VulHub opcional (Solr/Log4Shell, CGI Bash/Shellshock, httpd 2.4.49/CVE-2021-41773).
*   **Proxy reverso e ponto de bloqueio:** Nginx com blocklist dinâmica (`blocklist.conf`).
*   **Ingestão:** o Logstash interpreta o log JSON do Nginx e grava no Elasticsearch ou em uma lista do Redis (buffer em memória).
*   **Motor de detecção híbrido (`ips/`):** Isolation Forest como primeira camada; janelas de 5 segundos são enviadas a um LLM (via OpenRouter), que decide se há ataque e qual IP bloquear.
*   **Agentes adversários:** OWASP ZAP, Slowloris, uma "botnet" de exploits do VulHub e o replay do dataset rotulado CSIC 2010, sempre misturados com tráfego benigno realista.

## 3. Início Rápido

### 3.1 Pré-requisitos
*   Docker e Docker Compose v2.20+ (o usuário precisa rodar `docker` sem `sudo`)
*   Python 3.10+ no host (runner, análise e testes)
*   Uma chave da API OpenRouter (ou qualquer endpoint compatível com OpenAI) para execuções com LLM real, **com crédito na conta**
*   ~8 GB de RAM livre (heap de 2 GB do Elasticsearch, 2 GB do ZAP, 512 MB do Logstash)
*   Portas livres no host: 80, 5044, 9200; e 6380 (Redis), 7474/7687 (Neo4j) quando esses fatores forem usados

### 3.2 Configuração
```bash
cp .env.example .env                 # preencha OPENROUTER_API_KEY
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-gnn.txt --index-url https://download.pytorch.org/whl/cpu   # opcional: testes da GNN
pytest -q                            # testes offline (sem Docker, LLM simulado)
```

Durante os experimentos o detector **não** roda no Python do host: ele roda no container `ips-detector`, construído a partir de `docker/detector` com versões fixas (`requirements-detector.txt`, as mesmas do estudo original, mais PyTorch CPU). Todas as imagens de terceiros em `docker-compose.yml` estão fixadas por digest. As imagens são construídas automaticamente na primeira execução (a imagem do detector baixa o PyTorch, então o primeiro build leva alguns minutos).

### 3.3 Primeiras execuções
```bash
# 1. Pipeline completo sem custo de API (LLM simulado), ~20 min
python -m ips.run experiments/smoke.yaml
python -m ips.analyze runs/smoke
xdg-open runs/smoke/analysis/report.md

# 2. Condição do estudo original (só ZAP, bloqueio ativo, 10 min, LLM real)
./run.sh                                             # MODELO_IA=openai/gpt-4o-mini ./run.sh para trocar o modelo

# 3. Piloto com o modelo real (baseline e shadow, 3 cenários, 2 repetições, ~1,5 h)
python -m ips.run experiments/pilot.yaml --only baseline,+shadow --scenarios zap,slowloris,vulhub
python -m ips.analyze runs/pilot
```

## 4. Framework de Ablação

### 4.1 Uma flag por melhoria
Cada melhoria é um campo de `ips/config.py::DetectorConfig`. **Os valores padrão reproduzem a arquitetura original**, então uma mudança só tem efeito quando sua flag é ligada em um arquivo de experimento. As melhorias se dividem em quatro tipos:

| Issue | Nome no `ablation.yaml` | Campo(s) | Tipo |
|---|---|---|---|
| #18 alternativas de bloqueio de IP | fator `shadow` | `enforcement: active \| log_only \| ttl` (`ttl_s`) | detector |
| #15 explicabilidade | fator `explain` | `explain: true` (justificativa + tipo de ataque antes da decisão) | detector |
| #21 uso de recursos | fator `redis` | `log_buffer: redis` (o Elasticsearch não é iniciado) | ambiente |
| #17 detecção de Slowloris | fator `conn` | `conn_telemetry: true` (`conn_per_ip_threshold`) | detector |
| #13 knowledge graph, fases 1-3 | fator `kg` | `knowledge_graph: true` (`kg_backend`, `kg_similarity_threshold`, `kg_hunt_*`) | detector |
| #13 GNN, fase 4 | fator `gnn` | `gnn: true` (`gnn_*`) | detector |
| Retreino da camada 1 | fator `l1fit` | `iforest_fit: warmup`, `iforest_threshold_quantile` | detector |
| Campos estendidos do log | fator `richlog` | `rich_log: true` (`request`, `host`, `request_length` visíveis ao LLM/KG) | detector |
| Atalho seguro do KG | fator `kgsafe` (requer `kg`) | `kg_strict: true` (`kg_margin`, `kg_common_feature_ratio`, `kg_provisional_ttl_s`) | detector |
| #19 baseline sem LLM | braços `crs_pl1`, `crs_pl2` | `proxy: crs`, `crs_paranoia`, `pipeline: observe` | braço de comparação |
| Só LLM ("força bruta") | braço `llm_only` | `layer1: none` | braço de comparação |
| #17, #22, #16 | cenários | `slowloris`, `vulhub`, `csic` (além de `zap`, `zap_legacy`) | cenário |
| #15, #20, #21 | sempre ligado | modelo fixo + metadados completos da resposta, escores iForest/GNN por log, amostragem de CPU/RAM | instrumentação |

O que cada melhoria faz:

*   **Modo shadow (#18).** `log_only` registra o IP que *seria* bloqueado (`enforcement.csv`) sem alterar o Nginx, então o ataque continua e pode ser estudado. Logs de IPs já marcados deixam de abrir janelas (emulando o bloqueio). `ttl` aplica um bloqueio real que expira após `ttl_s`.
*   **Explicabilidade (#15).** O LLM precisa escrever uma `justificativa` e um `tipo_ataque` antes de `ataque_detectado`/`ip_alvo_bloqueio`. Ambos ficam em `windows.csv`.
*   **Buffer Redis (#21).** O Logstash grava em uma lista do Redis consumida pelo detector, e o Elasticsearch não é iniciado. CPU/RAM de todos os containers são sempre amostrados. Limites de recursos por serviço podem ser definidos no experimento (`resources:`).
*   **Telemetria de conexões (#17).** O Nginx só registra uma conexão Slowloris (status 408) quando ela expira. O detector lê `/proc/net/tcp` dentro do proxy a cada 2 s e abre uma janela quando um IP mantém `conn_per_ip_threshold` conexões ou mais.
*   **Knowledge graph (#13, fases 1-3).** Os logs viram um grafo no Neo4j (`IP → Endpoint / UserAgent / Token / Status`). Cada ataque confirmado pelo LLM gera uma `Signature`. Novos IPs cujo comportamento casa com uma assinatura (Jaccard ponderado por IDF ≥ limiar) são bloqueados sem chamar o LLM. Uma caça periódica (threat hunting) envia ao LLM perfis de IP de longo prazo (low-and-slow, muitas conexões, classes de payload). O grafo pode ser explorado em http://localhost:7474 (`neo4j` / `ips-research`).
*   **GNN (#13, fase 4).** Um autoencoder de grafo no estilo DOMINANT sobre o grafo IP–endpoint, treinado no período benigno de aquecimento e combinado ao iForest por OU lógico.
*   **Retreino da camada 1 (`l1fit`).** O `trafego_base.csv` original cobre só 7 rotas, então o iForest marca como anômala a maior parte das requisições benignas realistas. Com `iforest_fit: warmup` o modelo é retreinado nos logs do aquecimento benigno (`iforest_warmup_s`, padrão = `warmup_s` do experimento; mantém o modelo do CSV se chegarem menos de `iforest_min_warmup_samples` logs). `iforest_threshold_quantile: 0.01` põe o limiar de decisão nesse quantil dos escores do aquecimento (FPR alvo ≈ 1%). O `detector_summary.json` registra `iforest_fitted_on` e `iforest_threshold`.
*   **Campos estendidos do log (`richlog`).** O Nginx sempre registra `request` (linha crua da requisição), `host` e `request_length`, então o tráfego gravado pode ser reprocessado com ou sem eles. O Nginx rejeita alguns payloads (ex.: o traversal da CVE-2021-41773) com 400 antes de interpretá-los e deixa `request_uri` vazio; a linha `request` ainda carrega o payload. Por padrão esses campos são removidos antes da detecção (comportamento original); `rich_log: true` os expõe ao LLM e ao KG.
*   **Atalho seguro do KG (`kgsafe`).** `kg_strict: true` torna o atalho do KG conservador: features presentes em mais de `kg_common_feature_ratio` dos IPs (e as de status/método) recebem peso zero; um casamento também precisa superar a similaridade com perfis benignos conhecidos por `kg_margin` (IPs julgados benignos pelo LLM alimentam um `BenignProfile`); o bloqueio pelo KG é provisório (`kg_provisional_ttl_s`), e o IP volta ao LLM em vez de ser casado de novo. Use `python -m ips.calibrate` (4.7) para escolher `kg_similarity_threshold` sem ajustar nos dados de avaliação.
*   **OWASP CRS (#19).** ModSecurity + Core Rule Set fica *atrás* do Nginx da baseline (`proxy → CRS → Juice Shop`), então o formato do log é idêntico. Requisições bloqueadas pelo WAF aparecem como 403. O pipeline do LLM fica desligado (`pipeline: observe`).

### 4.2 Desenho experimental
O campo `design` do experimento expande os fatores listados em `factor_order`:

| Desenho | Configurações geradas | Responde |
|---|---|---|
| `baseline` | `baseline` | arquitetura original |
| `isolated` | `+shadow`, `+explain`, ... | efeito de cada melhoria sozinha |
| `cumulative` | `+shadow+explain`, ..., `all` | efeito do empilhamento na ordem de `factor_order` |
| `leave_one_out` | `all-shadow`, `all-kg`, ... | contribuição marginal dentro da pilha completa |
| `full_factorial` | todas as 2^k combinações | interações (caro) |

Configurações com o mesmo conjunto de fatores são geradas uma única vez, com nome canônico. Um fator pode declarar `requires:` (ex.: `kgsafe` requer `kg`): as dependências são adicionadas antes da deduplicação, então `+kgsafe` vira `+kg+kgsafe` e `all-kg` coincide com `all`. Os braços de comparação (`arms:`) são somados à matriz, e cada cenário em `scenarios:` a multiplica. A ordem das execuções é embaralhada dentro de cada repetição (`seed` fixo), para que variações de latência da API ou de carga do host ao longo do dia não se confundam com uma configuração.

### 4.3 Arquivos de experimento
```yaml
name: ablation            # saída em runs/<name>/
duration_s: 600           # janela de ataque
warmup_s: 60              # período só benigno antes do ataque (calibração da GNN e do l1fit)
repetitions: 33
seed: 42
base:                     # campos de DetectorConfig aplicados a todas as configurações
  model: openai/gpt-4o-mini-2024-07-18
factor_order: [shadow, l1fit, explain, richlog, redis, conn, kg, kgsafe, gnn]
factors:
  shadow: {enforcement: log_only}
  kg:     {knowledge_graph: true}
  kgsafe: {requires: [kg], kg_strict: true}   # dependência: +kgsafe vira +kg+kgsafe
  # ...
design: [baseline, isolated, cumulative, leave_one_out]
arms:
  llm_only: {layer1: none, enforcement: log_only}
  crs_pl1:  {proxy: crs, crs_paranoia: 1, pipeline: observe}
scenarios: [zap, slowloris, vulhub, csic]
resources:                # limites opcionais do docker compose
  elasticsearch: {cpus: "1.0", memory: 2g}
```

Experimentos disponíveis (`experiments/`):

| Arquivo | Finalidade |
|---|---|
| `ablation.yaml` | estudo principal: 9 fatores (28 configurações), 3 braços, 4 cenários |
| `ablation-replay.yaml` | fatores só de detector para o replay pareado (ver 4.6) |
| `pilot.yaml` | mesma matriz com janela de 300 s e 2 repetições (piloto com o modelo real) |
| `smoke.yaml` | validação do pipeline com LLM simulado, execuções curtas |
| `legacy.yaml` | condição original (usado pelo `run.sh`) |
| `detector-default.yaml` | configuração usada ao iniciar o container do detector manualmente |

Para adicionar uma melhoria: crie o(s) campo(s) em `DetectorConfig` (padrão = comportamento atual), use-os em `ips/detector.py` e declare um fator no arquivo de experimento. Nada mais precisa mudar.

### 4.4 Cenários
| Cenário | Tráfego | IP(s) do atacante |
|---|---|---|
| `zap` | varredura completa do OWASP ZAP + usuários benignos | `.101` |
| `zap_legacy` | só ZAP (condição do estudo original) | `.101` |
| `slowloris` | 900 conexões lentas + usuários benignos | `.102` |
| `vulhub` | Log4Shell, Shellshock e CVE-2021-41773 contra um sistema composto; 3 atacantes iniciando em 0 s, 120 s e 240 s + usuários benignos | `.103-.105` |
| `csic` | requisições rotuladas do CSIC 2010 reenviadas pelo proxy real + usuários benignos | `.110` (benignos do CSIC: `.60`) |

O ground truth vem dos IPs de origem fixos em `172.30.0.0/24`. Os usuários benignos (`docker/traffic/benign.py`) são `.51-.53` e cometem erros naturais (senha errada, rota digitada errado, chamadas sem autenticação). O cenário `csic` precisa do dataset em `datasets/csic2010/`: rode `datasets/fetch_csic.sh` (Kaggle CLI) ou `datasets/fetch_csic.sh /caminho/arquivos` (CSV do Kaggle ou os `.txt` originais). O script grava ou confere `datasets/csic2010.sha256`, e cada execução registra o SHA-256 dos arquivos usados em `run.json` (`datasets`). O runner se recusa a iniciar o `csic` sem o dataset.

### 4.5 Executando experimentos
```bash
python -m ips.run experiments/ablation.yaml --list                     # matriz, execuções pendentes, estimativa de tempo
python -m ips.run experiments/ablation.yaml                            # tudo
python -m ips.run experiments/ablation.yaml --only baseline,+kg --scenarios zap,vulhub --reps 5
python -m ips.run experiments/ablation.yaml --set temperature=0 --tag temp0   # sobrescreve um campo, diretório de saída separado
python -m ips.run experiments/ablation.yaml --keep-going               # não para se uma execução falhar
```

Cada execução: derruba a stack → sobe proxy, alvo, ingestão e serviços opcionais → inicia o tráfego benigno e o detector → espera `warmup_s` → inicia os atacantes → espera o detector terminar → salva logs, digests das imagens e amostras de recursos → derruba tudo. Execuções concluídas recebem o marcador `DONE` e são puladas, então um comando interrompido pode simplesmente ser executado de novo. Uma execução leva cerca de `warmup_s + duration_s + 1,5 min`.

Se o provedor do LLM responder 401, 402 ou 403 (chave inválida ou sem crédito), a execução é abortada e a matriz para, em vez de gravar resultados com todas as janelas em erro.

### 4.6 Replay pareado (mais barato, comparações mais fortes)
A matriz completa ao vivo é grande (≈3.700 execuções, ≈770 h com 33 repetições). Cada execução ao vivo guarda todos os logs normalizados (e as amostras de conexão) em `logs.jsonl`, então os fatores só de detector podem ser reexecutados **offline sobre exatamente o mesmo tráfego**, com relógio virtual: o tempo real passa a ser só a latência do LLM, e as comparações são pareadas (mesma entrada), o que elimina a variância do ambiente.

```bash
# 1. grave o tráfego uma vez por cenário/repetição (o modo shadow mantém o ataque completo)
python -m ips.run experiments/ablation.yaml --only +shadow --reps 33
# 2. aplique todas as configurações de detector ao tráfego gravado
python -m ips.replay experiments/ablation-replay.yaml --traffic runs/ablation/+shadow
# 3. a análise passa automaticamente para testes pareados
python -m ips.analyze runs/ablation-replay
```

Fatores que mudam o ambiente (buffer Redis, proxy CRS) são rejeitados pelo replay e precisam ser avaliados ao vivo. O bloqueio é **emulado** no replay (`replay_emulate_block: true`, padrão): depois que um IP é bloqueado, seus logs gravados são reescritos como o 403 que o Nginx teria devolvido (`request_time` 0, tamanho do corpo medido ao vivo). Assim o detector recebe o mesmo retorno de uma execução ao vivo em modo ativo. Uma verificação em uma execução VulHub deu, ao vivo vs replay: `attack_block_rate` 0,912 vs 0,921, `llm_calls` 27 vs 29. A *reação* do atacante ao bloqueio (ex.: desistir antes) não pode ser emulada.

### 4.7 Análise
```bash
python -m ips.analyze runs/ablation
python -m ips.analyze runs/ablation --metrics tokens_total,ttm_s,iforest_f1
```

Saídas em `runs/<experimento>/analysis/`:

| Arquivo | Conteúdo |
|---|---|
| `runs.csv` | uma linha por execução com todas as métricas |
| `summary.csv` | média, desvio e IC 95% por (cenário, configuração) |
| `comparisons.csv` | pares antes/depois: deltas, p-valores, p ajustado por Holm, d de Cohen |
| `report.md` | tabelas-resumo e diferenças significativas |
| `figures/` | gráficos de barras com IC 95% por métrica e distribuição dos escores do iForest por rótulo |

Comparações geradas: `isolated` (cada configuração vs `baseline`), `refinement` (um fator vs o fator de que depende, ex.: `+kg` → `+kg+kgsafe`), `cumulative` (cada passo do empilhamento vs o anterior), `loo` (`all` vs `all-<fator>`), `arm` (braços vs `baseline`). Testes: t de Welch e Mann-Whitney U para execuções ao vivo; t pareado e Wilcoxon para o replay; d de Cohen; correção de Holm-Bonferroni por (cenário, métrica, tipo de comparação).

Principais métricas:

| Grupo | Métricas |
|---|---|
| Custo | `llm_calls`, `tokens_total`, `tokens_per_call`, `cost_total`, `latency_mean`, `latency_p95`, `logs_to_llm_ratio`, `kg_decisions` |
| Detecção | `detected`, `ttm_s` (primeiro log do atacante → primeiro bloqueio), `attack_ip_recall`, `fp_ips` (IPs benignos bloqueados), `window_precision/recall/f1`, `ip_accuracy`, `attack_block_rate`, `benign_block_rate` |
| Camada 1 (#20) | `iforest_tp/fp/tn/fn`, `iforest_precision/recall/f1/fpr`, `iforest_auc_roc/auc_pr`, `gnn_*`, `layer1_*` (iForest OU GNN) |
| Recursos (#21) | `cpu_total_mean`, `mem_total_max_mb`, `<container>_cpu_mean`, `<container>_mem_max_mb` |

Calibração de um parâmetro sem ajustar nos dados reportados (replay; as repetições ímpares escolhem o valor e as pares o avaliam):

```bash
python -m ips.calibrate experiments/ablation-replay.yaml --config +kg+kgsafe \
    --traffic runs/ablation/+shadow --param kg_similarity_threshold \
    --values 0.4,0.5,0.6,0.7,0.8 --metric attack_ip_recall --fp-penalty 1
```
Objetivo: média(métrica) − fp_penalty · média(fp_ips), com empate decidido pelo menor consumo de tokens. Saída em `runs/calibration/<config>__<param>/` (`sweep.csv`, `evaluation.csv`, `calibration.json`).

### 4.8 Arquivos de uma execução
`runs/<experimento>/<config>/<cenario>/rep-NN/`:

| Arquivo | Conteúdo |
|---|---|
| `detector_config.json`, `config.json` | configuração efetiva do detector |
| `environment.json` | commit do git, flag de alterações locais, versões do Python e dos pacotes |
| `run.json` | fatores, perfis, timestamps (infra pronta, início do ataque, fim), digests das imagens, hashes dos datasets |
| `windows.csv` | toda decisão (LLM, KG, hunt): gatilho, logs enviados, contagens do ground truth, tokens, custo, latência, modelo/provedor/generation id servidos, decisão, explicação |
| `layer1.csv` | todo log: rótulo, features, escore/predição do iForest e da GNN |
| `enforcement.csv` | bloqueios, bloqueios shadow, expirações, IPs inválidos ou duplicados |
| `connections.csv` | conexões abertas por IP ao longo do tempo |
| `resources.csv` | CPU e memória por container (~1 s) |
| `logs.jsonl` | todos os logs normalizados (entrada do replay) |
| `resultados_pesquisa.csv` | formato legado usado por `resultados/gerar_graficos.py` |
| `*.log` | logs dos containers do detector e dos atacantes |

## 5. Executando o Detector Manualmente
```bash
COMPOSE_PROFILES=proxy-nginx,es,benign docker compose up -d --build   # laboratório + tráfego benigno
docker compose --profile detector up detector                         # usa experiments/detector-default.yaml

# ou no host, sobrescrevendo qualquer campo de DetectorConfig
python -m ips.detector --set llm_backend=mock --set enforcement=log_only --set output_dir=runs/manual
python -m ips.detector --set log_buffer=jsonl --set jsonl_path=runs/smoke/baseline/zap/rep-01/logs.jsonl \
                       --set llm_backend=mock --no-docker            # replay offline de uma execução

docker compose --profile '*' down --remove-orphans                    # limpeza
```
Sem `--config`, as variáveis históricas `MODELO_IA` e `ENFORCEMENT_MODE` continuam valendo. Com um arquivo de configuração, parâmetros experimentais nunca vêm do ambiente; só os endpoints são lidos dele (`IPS_ELASTICSEARCH_URL`, `IPS_REDIS_URL`, `IPS_NEO4J_URL`, `IPS_OUTPUT_DIR`).

## 6. Solução de Problemas
*   **Porta já em uso (80, 9200, 6380, 7687).** Pare o serviço conflitante. O Redis é publicado na 6380 de propósito, para não colidir com um Redis local.
*   **Logstash "unhealthy".** O healthcheck testa a porta syslog 5044 (a API HTTP na 9600 não responde em alguns hosts). A inicialização leva 30–60 s.
*   **SELinux (Fedora/RHEL).** Os bind mounts usam `:z` e o detector usa `security_opt: label=disable` para acessar o socket do Docker.
*   **Arquivos em `runs/` pertencentes ao root.** O container do detector roda com seu UID/GID (`HOST_UID`, `HOST_GID`, `DOCKER_GID`, definidos pelo runner). Ao iniciá-lo manualmente, exporte-os se forem diferentes de 1000/1000/964.
*   **O ZAP é encerrado.** O heap é fixado com `-Xmx2g`. Sem isso, o `zap.sh` dimensiona o heap pela RAM do host e estoura o limite do container. O ZAP leva ~60 s para começar a varredura.
*   **As primeiras requisições retornam 502.** Normal enquanto o Juice Shop inicializa. O runner espera uma resposta diferente de 5xx antes de iniciar o tráfego.
*   **"Abortado: ... 402".** A conta do OpenRouter está sem crédito. O limite configurado na chave é só um teto de gasto, não saldo. Adicione crédito e execute o mesmo comando de novo (execuções concluídas são puladas).

## 7. Limitações Conhecidas
*   As correções acima são fatores opcionais, para que seu custo seja medido em vez de presumido. Os padrões ainda reproduzem as limitações originais: iForest treinado no CSV, linha da requisição removida, atalho do KG permissivo.
*   O replay emula o efeito do bloqueio nos logs, mas não a reação do atacante a ele. Fatores cujo efeito depende dessa reação (ou do ambiente) precisam ser avaliados ao vivo.
*   O `kgsafe` reduz, mas não elimina, o risco de propagar um falso positivo do LLM. O TTL provisório limita o dano a `kg_provisional_ttl_s`.

## 8. Estrutura do Repositório
*   `ips/`: pacote do detector.
    *   `detector.py`: laço principal.
    *   `layer1.py` (iForest), `layer2.py` (LLM, prompts, backend simulado), `enforcement.py` (mitigação).
    *   `kg.py` (knowledge graph), `gnn.py` (autoencoder DOMINANT), `conn.py` (telemetria de conexões).
    *   `sources.py` (fontes Elasticsearch / Redis / JSONL), `records.py` (normalização dos logs), `telemetry.py` (saídas da execução), `config.py` (todas as flags).
    *   `matrix.py` (expansão do desenho), `run.py` (runner), `replay.py` (replay pareado), `scenarios.py`, `resources.py` (amostragem de CPU/RAM), `analyze.py` (estatística e figuras), `calibrate.py` (calibração de limiares com divisão ímpar/par).
*   `experiments/`: definições dos experimentos.
*   `docker/detector/`: imagem do detector.
*   `docker/traffic/`: usuários benignos, Slowloris, atacante VulHub, replay do CSIC.
*   `docker/nginx/`: seleção do backend do proxy (direto ou via CRS).
*   `docker/vulhub/`: CGI vulnerável para o Shellshock.
*   `logstash/pipeline/`: pipelines de ingestão (`elasticsearch.conf`, `redis.conf`).
*   `datasets/`: datasets externos (não versionados; `fetch_csic.sh` baixa e confere, ver `datasets/README.md`).
*   `runs/pilot/`: análise do piloto com o modelo real (só `analysis/` é versionado; ver `runs/pilot/README.md`).
*   `tests/`: testes offline (pytest).
*   `IsolationForest/`: tráfego de referência (`trafego_base.csv`), seu gerador e o detector monolítico original (mantido só como referência).
*   `resultados/`: resultados históricos do artigo e scripts de gráficos.
*   `run.sh`: execução única na condição original.

## 9. Considerações Éticas e Licenciamento
Este software é disponibilizado exclusivamente para pesquisa acadêmica. Todas as simulações de ataque são feitas dentro de uma rede Docker isolada, contra aplicações intencionalmente vulneráveis. Os payloads de exploit apontam apenas para hosts inexistentes (`*.invalid`) e executam comandos somente de leitura. O código-fonte é licenciado para reúso acadêmico aberto.

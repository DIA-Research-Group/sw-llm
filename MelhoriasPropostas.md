# Roteiro de Apresentacao: Analise e Melhorias do IPS Autonomico

Este documento consolida a analise completa, unindo as descricoes estruturais aos detalhes tecnicos, linhas de codigo, conceitos didaticos e links de referencia para guiar a apresentacao.


## 1. Expansao do Escopo de Testes

### 1.1 Expansao de Alvos (Aplicacoes: DVWA e Vulhub)
*   **Estado Atual:** O teste e realizado exclusivamente contra a aplicacao OWASP Juice Shop, que possui um perfil especifico de vulnerabilidades (Node.js) e e intencionalmente ruidosa.
    *   *Linha no codigo:* `docker-compose.yml` (Linha 29) -> `image: bkimminich/juice-shop`
*   **Estado Proposto:** Adicionar novos alvos com stacks tecnologicas diferentes, como o DVWA (PHP/MySQL) para testar niveis de dificuldade, e o Vulhub para testar vulnerabilidades em conteineres reais.
    *   **Conceito/Termo Tecnico:** O **DVWA** (Damn Vulnerable Web App) e uma aplicacao PHP propositalmente fragil com niveis de dificuldade ajustaveis. O **Vulhub** e um ecossistema que prove ambientes com vulnerabilidades reais e conhecidas (CVEs).
    *   **Referencia:** [DVWA GitHub](https://github.com/digininja/DVWA), [Vulhub](https://vulhub.org/)
*   **Objetivo da Melhoria:** Provar que a arquitetura nao tem vies para uma tecnologia especifica e consegue detectar payloads complexos (ex: JNDI lookups) em diferentes formatos de log gerados pelo Nginx.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio (1 a 2 semanas). Exige configurar novos conteineres no `docker-compose.yml`, novos scripts de provisionamento e adaptar o script de ataque.
    *   **Impacto:** **Alto.** A validacao cruzada com diferentes alvos aumenta drasticamente o peso cientifico da pesquisa.

### 1.2 Expansao de Vetores de Ataque
*   **Estado Atual:** Utilizacao primaria do ZAP em *Active Scan*, focado em ataques ruidosos e volumetricos.
    *   *Linha no codigo:* `docker-compose.yml` (Linha 109) -> `command: zap-baseline.py -t http://nginx-proxy:80 -d`
*   **Estado Proposto:** Incorporar ataques *Low and Slow* (ex: Slowloris), Injecao Direcionada (ex: SQLMap com limitador de RPS) e DDoS de Aplicacao (Hping3/GoldenEye).
    *   **Conceito/Termo Tecnico:** Ataques **Low and Slow** esgotam recursos do servidor mantendo conexoes abertas enviando dados devagar, sem gerar grandes volumes de trafego, "enganando" firewalls tradicionais.
    *   **Referencia:** [Slowloris](https://github.com/gkbrk/slowloris), [SQLMap](https://sqlmap.org/)
*   **Objetivo da Melhoria:** Validar os limites da Camada 1 (iForest) contra ataques lentos e prolongados, garantir que o LLM detecta anomalias semanticas puras sem depender do gatilho de volume.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio (1 a 2 semanas). Temos que criar scripts orquestradores para disparar ferramentas diferentes e correlacionar tempos.
    *   **Impacto:** **Alto.** Demonstra a eficacia contra ameacas modernas.

---

## 2. Metricas e Benchmarks

### 2.1 Novas Metricas Praticas de Seguranca e Infra
*   **Estado Atual:** As metricas limitam-se a acuracia, latencia e tokens.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 34) -> `def save_research_metric(model_name, tokens_consumed, api_latency, blocked_ip, logs_count):`
*   **Estado Proposto:** Medir Taxa de Falsos Positivos (FPR) e Falsos Negativos (FNR) sob trafego cruzado, *Time-to-Mitigate* (TtM), e *Overhead* de CPU/Memoria.
    *   **Conceito/Termo Tecnico:** **Overhead** e a carga computacional que a solucao adiciona ao sistema. Verificar se a protecao consome mais CPU que a aplicacao. **Time-to-Mitigate (TtM)** e o tempo desde o log ate a regra bloqueadora ser aplicada.
    *   **Referencia:** [Docker Stats (Monitoramento)](https://docs.docker.com/reference/cli/docker/stats/)
*   **Objetivo da Melhoria:** Provar a viabilidade da solucao em producao, visto que um FPR alto invalida o sistema e o *overhead* demonstra a eficiencia da Camada 1 local.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo/Medio (3 a 5 dias).
    *   **Impacto:** **Critico.** Pesquisas precisam de metricas validadas.

### 2.2 Benchmarking em Datasets Publicos (CSIC 2010, CIC-IDS-2017)
*   **Estado Atual:** Testes baseados inteiramente em dados gerados em laboratorio proprio (ZAP vs. Juice Shop).
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 150) -> `df_batch = pd.DataFrame([hit['_source'] for hit in hits])` (Lendo do Elasticsearch em tempo real).
*   **Estado Proposto:** Rodar o modelo sobre datasets publicos consagrados de logs web com ataques rotulados.
    *   **Conceito/Termo Tecnico:** O **CIC-IDS-2017** e um conjunto de dados academico padrao com milhoes de pacotes de trafego rotulados de forma rigorosa como benigno ou ataque. Usa-lo prova que o sistema funciona em redes que nao foram criadas pelo proprio pesquisador.
    *   **Referencia:** [CIC-IDS-2017 Dataset](https://www.unb.ca/cic/datasets/ids-2017.html)
*   **Objetivo da Melhoria:** Permitir a comparacao direta (baseline) com outros artigos que usam a mesma base, provando cientificamente o valor do modelo.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio (1 a 2 semanas).
    *   **Impacto:** **Critico.** Aumenta a reprodutibilidade.

### 2.3 Comparacao com Padroes da Industria (ModSecurity/Fail2Ban)
*   **Estado Atual:** Comparacao focada apenas entre abordagens de LLM (Hibrido vs. LLM Puro).
    *   *Linha no codigo:* Nao temos.
*   **Estado Proposto:** Rodar os mesmos ataques contra um WAF tradicional (ModSecurity + OWASP CRS) ou Fail2Ban para estabelecer baseline.
    *   **Conceito/Termo Tecnico:** Um **WAF (Web Application Firewall)** protege o servidor bloqueando padroes maliciosos na Camada 7. O **ModSecurity** e o WAF de codigo aberto mais usado no mundo. O projeto propoe superar metodos estaticos com LLMs, logo, precisa provar ser melhor.
    *   **Referencia:** [ModSecurity](https://github.com/owasp-modsecurity/ModSecurity), [OWASP CRS](https://coreruleset.org/)
*   **Objetivo da Melhoria:** Provar que a IA consegue pegar ataques que regras estaticas deixam passar, justificando a adocao de LLMs.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio/Alto (2 semanas).
    *   **Impacto:** **Alto.** Demonstra a vantagem competitiva real do sistema.

### 2.4 Metricas Especificas para a Camada 1 (iForest)
*   **Estado Atual:** Acuracia global reportada, sem detalhar a efetividade exclusiva do filtro inicial de anomalias (iForest).
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 163) -> `anomalies_detected = df_batch[df_batch['anomaly_score'] == -1]`
*   **Estado Proposto:** Gerar Matriz de Confusao, Precision, Recall e F1-Score especificamente para o iForest antes da chamada do LLM.
    *   **Conceito/Termo Tecnico:** **Recall (Revocacao)** mede de todos os ataques que *realmente aconteceram*, quantos o modelo conseguiu detectar. Se o Recall da Camada 1 for baixo, o ataque nao chega no LLM.
    *   **Referencia:** [Scikit-learn Metrics](https://scikit-learn.org/stable/modules/classes.html#module-sklearn.metrics)
*   **Objetivo da Melhoria:** Mostrar quantitativamente se a Camada 1 nao esta deixando passar ataques reais que deveriam ir para o LLM.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo (1 a 2 dias).
    *   **Impacto:** **Critico.** Justifica matematicamente o uso do filtro.

---

## 3. Correcoes Arquiteturais (O Modelo)

### 3.1 Cegueira Dimensional e de Sequencia no iForest
*   **Estado Atual:** iForest utiliza apenas 3 features tabulares soltas e avalia requisicoes individualmente sem percepcao temporal.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 73) -> `features = ['request_time', 'status', 'body_bytes_sent']`
*   **Estado Proposto:** Criar features agregadas e discutir modelos sensiveis a sequencia (LSTM/Transformers).
    *   **Conceito/Termo Tecnico:** **LSTM (Long Short-Term Memory)** e um tipo de rede neural que possui memoria de longo prazo, entendendo que 10 requisicoes que parecem normais sozinhas sao, na verdade, um ataque de forca bruta se analisadas em *sequencia*.
    *   **Referencia:** [Understanding LSTMs](https://colah.github.io/posts/2015-08-Understanding-LSTMs/)
*   **Objetivo da Melhoria:** Reduzir falsos positivos oriundos de usuarios lentos ou downloads pesados.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio para features, Alto (Meses) para trocar para LTSM ou transformadores.
    *   **Impacto:** **Alto.** para features e **Medio** para LSTM.

### 3.2 Taxa de Contaminacao e Concept Drift
*   **Estado Atual:** O artigo reporta o uso de `contamination='auto'`, delegando a estimativa ao algoritmo de forma estatica no treinamento.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 75) -> `model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42)` *(O codigo esta fixado em 0.1, mas o artigo em 'auto')*
*   **Estado Proposto:** Implementar limiares dinamicos para a contaminacao que se auto-ajustem em tempo de execucao (Estrategia de Re-treinamento Continuo).
    *   **Conceito/Termo Tecnico:** **Concept Drift** ocorre quando o comportamento "normal" do usuario muda com o tempo. Um modelo estatico envelhece e comeca a gerar Falsos Positivos. **MLOps** e a disciplina que gerencia o ciclo de vida do modelo em producao.
    *   **Referencia:** [Concept Drift in Machine Learning](https://machinelearningmastery.com/gentle-introduction-concept-drift-machine-learning/)
*   **Objetivo da Melhoria:** Evitar que o sistema degrade e classifique trafego legitimo recem-introduzido como anomalia.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio (1 a 2 semanas).
    *   **Impacto:** **Alto.** Mesmo com janelas deslizantes simples.

### 3.3 Exaustao da Janela de Contexto (Camada 2)
*   **Estado Atual:** Todos os logs de uma janela de 5 segundos sao enviados ao LLM e fatiados de forma arbitraria.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 179) -> `sanitized_context = json.dumps(context_collection[:50], indent=2)`
*   **Estado Proposto:** Ordenar as anomalias detectadas pelo *score* do iForest e amostrar apenas os "Top 50" mais anomalos para o LLM.
    *   **Conceito/Termo Tecnico:** **Janela de Contexto** e a memoria de curto prazo do LLM. Limitar aos itens estatisticamente mais suspeitos otimiza o uso do limite de tokens e melhora a deteccao.
*   **Objetivo da Melhoria:** Evitar *crashes* na API, economizar custos e melhorar a latencia da resposta.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo (1 dia).
    *   **Impacto:** **Alto.**

### 3.4 Trafego Benigno Irrealista
*   **Estado Atual:** O trafego normal e idealizado (via CSV estatico), sem erros naturais que usuarios cometem.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 66) -> `df_base = pd.read_csv(base_traffic_csv)`
*   **Estado Proposto:** Construir um script gerador de ruido benigno simultaneo.
    *   **Conceito/Termo Tecnico:** **Noise Generation** visa criar ruido (erros normais de usuario via Selenium ou *requests*) para treinar o filtro a nao ser excessivamente sensivel, reduzindo Falsos Positivos.
*   **Objetivo da Melhoria:** Provar que o modelo nao e fragil.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo/Medio (3 dias).
    *   **Impacto:** **Alto.** torna a avaliacao muito mais proxima da realidade.

---

## 4. Seguranca, Resiliencia e Compliance da Solucao

### 4.1 Vulnerabilidade a Prompt Injection e Alucinacao de Formato
*   **Estado Atual:** Dados brutos (`User-Agent`, `URI`) sao jogados no *prompt*.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 197) -> `{"role": "user", "content": f"Observability Data:\n{sanitized_context}"}` e o parser tosco na Linha 228 (`if raw_content.startswith("```"):`).
*   **Estado Proposto:** Adicionar delimitadores e sanitizacao rigida no *prompt*. Validar a saida com Regex.
    *   **Conceito/Termo Tecnico:** **Prompt Injection** e quando um atacante envia dados num formato que confunde a IA, fazendo-a ignorar instrucoes originais (ex nosso caso: colocar na URI um comando para a IA aprovar o IP).
    *   **Referencia:** [OWASP Top 10 for LLMs - Prompt Injection](https://genai.owasp.org/llm-top-10/)
*   **Objetivo da Melhoria:** Garantir que o proprio sistema de seguranca nao possua uma vulnerabilidade critica de injecao.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo (1 a 2 dias).
    *   **Impacto:** **Critico.** Indispensavel para a seguranca do sistema.

### 4.2 Risco de Negacao de Servico Financeira (FDoS) e Gargalo I/O
*   **Estado Atual:** Nao ha limitacao de chamadas a API. Chamadas sincronas bloqueiam o pipeline.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 203) -> `api_response = requests.post(...)`
*   **Estado Proposto:** Implementar *Rate Limiting* estrito, *circuit breakers* e chamadas assincronas (`asyncio`).
    *   **Conceito/Termo Tecnico:** **E/S Assincrona (Async I/O)** permite que o programa continue analisando logs locais enquanto espera a resposta da API. **FDoS (Financial Denial of Service)** e um ataque focado em esgotar o orcamento de nuvem da vitima fazendo-a disparar requisicoes milionarias a API.
    *   **Referencia:** [Python Asyncio](https://docs.python.org/3/library/asyncio.html)
*   **Objetivo da Melhoria:** Evitar falencia devido a exaustao de chamadas e garantir alta concorrencia.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio (1 semana).
    *   **Impacto:** **Critico.** vital para estabilidade de custos.

### 4.3 Violacao de LGPD/GDPR (Privacidade)
*   **Estado Atual:** Logs brutos sao despachados para APIs externas, violando leis de privacidade.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 179) -> O *JSON Serialize* nao mascara IPs/tokens de usuarios inocentes capturados no batch.
*   **Estado Proposto:** *Data Masking*/Anonimizacao por Regex na Camada 1 antes de enviar para o LLM.
    *   **Conceito/Termo Tecnico:** **Data Masking** e o processo de obscurecer PII (*Personally Identifiable Information*, como nomes, tokens e CPFs) usando *hashes* ou `[REDACTED]` para estar em conformidade legal (LGPD).
*   **Objetivo da Melhoria:** Fazer com que o sistema seja aderente a regulamentacao (Compliance).
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo (2 dias).
    *   **Impacto:** **Baixo.**

### 4.4 Limitacoes do Bloqueio: IP Singular, Banimentos Perpetuos e SPOF
*   **Estado Atual:** Bloqueio eterno e sincrono por IPv4. Se o modelo errar, trafego morre para sempre.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 261) -> `f.write(f"deny {threat_ip};\n")`
*   **Estado Proposto:** Adicionar TTL (Time-To-Live) para remover IPs banidos apos horas e extrair "Assinaturas" alem de IPs.
    *   **Conceito/Termo Tecnico:** Um **IP Singular** bloqueado no Nginx pune a todos (ex: CGNAT). O **TTL** remove regras antigas garantindo que o servidor nao perca performance processando regras infinitas. **SPOF (Single Point of Failure)** indica que o script concentra todo o risco da protecao.
*   **Objetivo da Melhoria:** Evoluir o bloqueio L4 para L7 e preservar a disponibilidade do servico ao longo do tempo.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Alto (2 a 3 semanas).
    *   **Impacto:** **Medio.** Considerar lista com ataques.

### 4.5 Termos, Topologia e Ameacas
*   **Estado Atual:** Promete prevencao ativa mas sofre latencia usando Elasticsearch como buffer de transito de 5s.
    *   *Linha no codigo:* `docker-compose.yml` (Linhas 47-62) -> Banco Elasticsearch e muito pesado para memoria volatil.
*   **Estado Proposto:** Ajustar o termo para **IPS Reativo Assincrono**, usar `X-Forwarded-For` no Nginx, e considerar Redis.
    *   **Conceito/Termo Tecnico:** O **Elasticsearch** possui alta latencia por persistir tudo em disco. O **Redis** armazena os dados na Memoria RAM, permitindo velocidade quase instantanea (ideal para buffers). O **X-Forwarded-For** e o cabecalho HTTP que diz o IP real caso haja uma Cloudflare na frente.
    *   **Referencia:** [Redis](https://redis.io/)
*   **Objetivo da Melhoria:** Ser honesto metodologicamente e reduzir latencia de I/O de disco.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo para texto, Medio para Redis.
    *   **Impacto:** **Alto.** As modificacoes metodologicas sao essenciais.

---

## 5. Metodologia Cientifica e Explicabilidade (XAI)

### 5.1 Falta de Explicabilidade (XAI)
*   **Estado Atual:** O LLM atua sem explicar, devolvendo apenas a decisao de bloqueio e o IP.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 195) -> O Prompt so pede: `{\"ataque_detectado\": bool, \"ip_alvo_bloqueio\": \"...\"}`
*   **Estado Proposto:** Forcar o LLM a gerar um campo `"justificativa"` ou `"chain_of_thought"` no JSON.
    *   **Conceito/Termo Tecnico:** **XAI (Explainable AI)** busca tornar as decisoes da maquina compreensiveis. Forcar o modelo a escrever uma justificativa **antes** da decisao (Chain-of-Thought) nao apenas prove explicabilidade para auditoria humana, mas melhora matematicamente a precisao da IA, forcando-a a "raciocinar".
    *   **Referencia:** [Chain-of-Thought Prompting Elicits Reasoning](https://arxiv.org/abs/2201.11903)
*   **Objetivo da Melhoria:** Permitir auditoria humana, algo obrigatorio em qualquer SOC de verdade.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Baixo (1 dia).
    *   **Impacto:** **Alto.** Excelente para explicabilidade. Pode agregar delay.

### 5.2 Lacunas de Reprodutibilidade e Estatistica
*   **Estado Atual:** Faltam detalhes de hiperparametros (Grid Search), teste-T e fixacao de versao do modelo de IA.
    *   *Linha no codigo:* `IsolationForest/detector.py` (Linha 182) -> `llm_model = os.getenv("MODELO_IA", "openai/gpt-4o-mini")` (A API vai pegar sempre a versao generica/mutavel, e nao uma versao chumbada).
*   **Estado Proposto:** *Version Pinning*, Teste-T/ANOVA e discussao sobre Green AI.
    *   **Conceito/Termo Tecnico:** **Version Pinning** e fixar a versao exata (ex: `gpt-4o-mini-2024-07-18`) para reprodutibilidade. **Green AI** e pesquisar a IA focada em eficiencia e reducao da pegada de carbono, justificando a sua arquitetura hibrida de filtragem local.
*   **Objetivo da Melhoria:** Blindar o artigo contra rejeicoes baseadas em falta de rigor metodologico.
*   **Drawbacks:**
    *   **Tempo de Implementacao:** Medio (1 semana) para rodar os testes estatisticos.
    *   **Impacto:** **Alto.** Resultados so sao validos se forem reprodutiveis e matematicamente solidos.

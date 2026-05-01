# 🛡️ Identificação e Reação a Ciberataques com LLMs

Repositório dedicado à pesquisa científica sobre a viabilidade e eficácia da utilização de Modelos de Linguagem de Grande Porte (LLMs) na análise de logs, identificação de ameaças e resposta automatizada a ataques cibernéticos.

---

## 📌 Questão de Pesquisa

**Modelos de linguagem de grande porte podem ser usados de forma eficaz para a identificação e reação automatizada a ataques cibernéticos?**

---

## 🧪 Hipóteses

O escopo da pesquisa busca validar se os LLMs são capazes de atuar ativamente na segurança defensiva, testando as seguintes premissas:

1. **Detecção:** LLMs conseguem identificar ataques cibernéticos de forma precisa a partir de dados de observabilidade.
2. **Rastreabilidade:** LLMs conseguem identificar a origem (vetor ou IP) dos ataques.
3. **Mapeamento de Impacto:** LLMs conseguem identificar com exatidão a parte do sistema (microsserviço, banco de dados, etc.) que está sob risco.
4. **Resposta a Incidentes:** LLMs conseguem criar um plano de ação em tempo razoável e executável (ex: gerar comandos para desativar um serviço na AWS ou isolar um contêiner via Docker).

---

## 📊 Variáveis de Análise

Para medir o sucesso e a eficiência das hipóteses levantadas, o projeto monitora as seguintes métricas quantitativas:

* **Taxa de Falsos Positivos:** A frequência com que o modelo sinaliza operações legítimas como atividades maliciosas.
* **Tempo para Identificação:** O tempo decorrido entre o início do ataque simulado e a detecção pelo LLM.
* **Quantidade de Tokens:** O volume de contexto consumido para analisar os logs e gerar a resposta (impactando diretamente no custo e na latência).
* **Tempo para Mitigação:** O tempo gasto pelo LLM para formular o plano de ação ou executar o bloqueio da ameaça.

---

## 🛠️ Arquitetura e Ambiente de Testes



Para validar as hipóteses, utilizamos um laboratório de testes que simula um ambiente de produção moderno, submetido a estresse e intrusões controladas:

### Sistema Alvo
* Arquitetura de microsserviços.
* Componentes incluídos: APIs REST, Bancos de Dados (relacionais/NoSQL) e Message Brokers.

### Simulação de Ataques (Red Team)
* Utilização de softwares de varredura e exploração de vulnerabilidades.
* Ferramentas ativas: *Nessus Scan*, entre outros scripts de simulação de tráfego malicioso.

### Observabilidade e Coleta de Dados
* Stack de monitoramento responsável por agregar logs, métricas e rastreamentos do sistema alvo.
* Estes dados são formatados e utilizados como *prompt context* para a tomada de decisão do LLM.

---

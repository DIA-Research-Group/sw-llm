O Gemini disse

1. Referência Bibliográfica
SAHEED, Yakub Kayode; CHUKWUERE, Joshua Ebere. Autonomous LLM Agent: A Memory-Augmented, Edge-Optimized SHAP Explanations With Zero-Day Attack Resilience in IoT/Industrial IoT Networks.  IEEE Internet of Things Journal, v. 13, n. 7, p. 14213-14228, 1 abr. 2026. 

2. Palavras-chave
Anomaly detection, Claude Sonnet, DeepSeek R1, explainable artificial intelligence (AI), GPT-40-mini, Internet of Things (IoT)/Industrial IoT (IIoT), large language models (LLMs) agent, zero-day attack. 

3. Objetivo
Introduzir o "Anomaly-Agent", uma estrutura de deteção de anomalias explicável e alimentada por Modelos de Linguagem de Grande Porte (LLMs) para ambientes de periferia (edge) IoT e IIoT. O sistema procura responder a ataques de dia zero (zero-day) em evolução, fornecendo explicações baseadas no método SHAP e permitindo a personalização da sensibilidade da deteção. 

4. Metodologia
O estudo propõe um canal de raciocínio seguido de ação (inspirado no framework ReAct), utilizando o LLM DeepSeek R1 como motor principal. O agente LLM é dotado de um espaço de ação com ferramentas específicas: extração de dados, pré-processamento (incluindo seleção de características orientada por SHAP e quantização), ferramentas de classificação (modelos de Machine Learning leves, como SVM, Random Forest e Naïve Bayes), recuperação de conhecimento externo (RAG consultando bases de dados como MITRE ATT&CK e CVE) e uma ferramenta de agregação de memória de longo prazo para casos históricos. A avaliação foi conduzida utilizando os conjuntos de dados Edge-IIoTset (específico para IIoT) e CIC-IoT2023 (IoT geral). 

5. Resultados
O Anomaly-Agent atingiu uma exatidão binária de 96% no conjunto de dados Edge-IIoTset e de 89% no CIC-IoT2023, mantendo uma Taxa de Falsos Alarmes (FAR) inferior a 0,04 em ambos os casos. O F1-Score para classificação multiclasse fixou-se em 0,93 (Edge-IIoTset) e 0,82 (CIC-IoT2023). Na deteção de ataques de dia zero, o sistema alcançou um recall de 65%, superando tanto os modelos de ML tradicionais como as linhas de base de LLMs (GPT-4o, Claude 3.5 Sonnet e GPT-4o-mini). Adicionalmente, a implementação demonstrou eficiência computacional em dispositivos com recursos limitados, operando com baixa latência e reduzida pegada de memória num Raspberry Pi 4. 

6. Conclusão em relação à pesquisa
Este artigo é uma peça fundamental para sustentar a Fase 4 (Orquestração de Mitigação) e a Fase 5 (Medição e Análise) da sua arquitetura metodológica. Ele prova estatisticamente que a utilização de LLMs isolados falha no contexto da cibersegurança devido à limitação de tokens e propensão a falsos positivos. A solução encontrada pelos autores valida a sua abordagem: o LLM não deve ser um classificador passivo, mas um "agente orquestrador" que cruza os dados dos logs com regras e históricos. Além disso, a funcionalidade do Anomaly-Agent de ajustar dinamicamente a sensibilidade de deteção (modo agressivo vs. modo conservador) valida de forma empírica a tese de que a injeção de "Políticas Operacionais" no seu prompt será suficiente para instruir o LLM a filtrar os falsos positivos do Juice Shop induzidos pelos alertas do Nessus.

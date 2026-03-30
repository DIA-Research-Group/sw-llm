1. Referência Bibliográfica:
SUDHEER, Arjun; CHOU, Chia-Hong; KUMAR, Shubham. Demo: A Real-time Multi-Agent Network Attack Detection and Incident Response System. Em: 2025 Silicon Valley Cybersecurity Conference (SVCC). IEEE, 2025.

2. Palavras-chave:
Large Language Model (LLM), Network Attack, Intrusion Detection System (IDS), Retrieval Augmented Generation (RAG), ReAct agent.

3. Objetivo da Pesquisa:
Propor um sistema multi-agente em tempo real para detectar ataques de rede e reagir a eles dinamicamente, integrando modelos de linguagem de grande porte (LLMs) com técnicas de Geração Aumentada por Recuperação (RAG).

4. Arquitetura e Metodologia:
A arquitetura metodológica do sistema opera através de um fluxo de quatro estágios, englobando pré-processamento de dados, detecção de ataques, sistema de resposta e agente de recomendação. A pesquisa usa o ACI IoT Network Dataset 2023, processando arquivos de captura de tráfego de rede (PCAP) convertidos para o formato CSV. Durante o pré-processamento, a dimensionalidade dos dados foi reduzida de 84 para 16 atributos. A fase de detecção é dividida estruturalmente: a pré-detecção emprega um classificador tradicional Random Forest para segregar tráfego benigno de malicioso. Em seguida, a pós-classificação utiliza um conjunto de quatro modelos (Random Forest, XGBoost, MLP e KNN) para determinar o tipo de ataque por meio de votação majoritária. O modelo de linguagem de grande porte (LLM) não atua como sensor primário, sendo invocado apenas como um agente de rotulagem para desempate quando os classificadores discordam. Para a mitigação, o sistema de resposta orquestra ações em uma arquitetura de Redes Definidas por Software (SDN), utilizando o emulador Mininet e o controlador Ryu para bloquear ou redirecionar ameaças nos switches virtuais. Paralelamente, o agente de recomendação aplica Geração Aumentada por Recuperação (RAG) para consultar bancos de dados como o National Vulnerability Database (NVD) e a API do ArXiv, gerando um painel de resposta a incidentes.

5. Resultados:
Os resultados empíricos estabelecem linhas de base rigorosas para a avaliação de sistemas de detecção. O estágio de pré-detecção registrou uma acurácia de 0,993. O mecanismo de votação majoritária na pós-classificação alcançou índices de 0,981 para precisão, recall e F1-Score. Na avaliação de qualidade do texto gerado pelo sistema RAG, as métricas apontaram uma fidelidade de 93,2%, indicando forte suporte do contexto recuperado para as afirmações do LLM, e uma relevância semântica de 0,78.

6. Conclusão em relação à pesquisa:
O titúlo sugere operação em realtime, entretanto, o sistema foi validado contra capturas de tráfego estáticas transformadas em tabelas csv, não há injeção de payloads em serviços vulneráveis.
Esse artigo evita usar LLMs para processar telemetria primária devido ao custo. Com o uso de Random Forest como filtro, há uma redução no consumo de tokens, mas a autonomia do LLM também é reduzida.
Acredito que Nessus x JuiceShop será mais rigoroso se o F1 score ficar próximo de 0,981 sem algoritmos de classificação menores.

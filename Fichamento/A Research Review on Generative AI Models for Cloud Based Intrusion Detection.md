1. Referência Bibliográfica:
KHAN, Minhaj; VIBHUTE, Amol D. A Research Review on Generative AI Models for Cloud Based Intrusion Detection. Em: 2025 International Conference on Innovations and Emerging Technologies In AI & Communication Systems (IETACS). IEEE, 2025.

2. Palavras-chave:
Cloud-based intrusion detection, generative AI, GANs, VAEs, GPT, Diffusion Models.

3. Objetivo:
O estudo investiga como técnicas de modelagem generativa podem identificar vulnerabilidades em infraestruturas de nuvem, mesmo diante da escassez de dados de treinamento extensos, paisagens de ameaças variadas e anomalias constantes. Ele foca na comparação de Redes Adversárias Generativas (GANs), Autocodificadores Variacionais (VAEs), Transformadores Pré-treinados Generativos (GPT) e modelos de difusão para aprimorar os sistemas de detecção de intrusões.

4. Metodologia:
A pesquisa conduz uma análise comparativa das arquiteturas dos quatro modelos generativos, avaliando seus fundamentos teóricos, mecanismos de criação de dados sintéticos, implementações práticas e custo computacional. A avaliação utiliza métricas de desempenho padronizadas, incluindo acurácia, precisão, recall e F1-Score, coletadas a partir da aplicação teórica e prática desses modelos em datasets reconhecidos, como NSL-KDD, UNSW-NB15, HDFS, IoT, CICIDS e dados de redes industriais.

5. Resultados:
A análise demonstra que não existe um modelo único ideal; a escolha depende da natureza da ameaça, dos recursos disponíveis e das características do dataset. GANs e modelos de difusão entregam alta qualidade na geração de dados sintéticos, sendo altamente eficazes para resolver o problema de desbalanceamento de classes de ataque. VAEs apresentam o melhor equilíbrio entre desempenho e demanda computacional, sendo eficazes na compressão e detecção de anomalias com baixo consumo de memória, embora suas representações latentes possam apresentar instabilidade em situações com múltiplas classes. Modelos baseados em difusão e GPT entregaram os resultados de detecção mais precisos e exatos, com o GPT atingindo 99,90% de acurácia, mas ambos exigem recursos computacionais substanciais e modelos de grande porte, dificultando seu uso em ambientes com recursos limitados.

6. Conclusão em relação à pesquisa:
Este documento consolida a fundamentação teórica do projeto. Ele valida empiricamente a utilidade do GPT na compreensão contextual de logs de sistema e tráfego de rede para identificação em tempo real, sustentando a escolha de um LLM para um experimento empírico. Simultaneamente, ele fornece a justificativa técnica exata do porquê o escopo focado em medição de desempenho é relevante: a literatura prova que o GPT possui altíssima precisão, mas falha no custo computacional e na exigência de infraestrutura. As variáveis de "Quantidades de Tokens", "Tempo para identificação" e "Tempo para mitigação" irão medir empiricamente quão severo é essa falta
 de recursos quando o LLM é exposto a tráfego hostil contínuo do Nessus contra a aplicação de testes.

1. Referência Bibliográfica
PAWANA, I. W. A. J.; PURNAMA, F.; LINAWATI; KIM, Y.; YOU, I. Generative AI for Cybersecurity: LLM-Driven Attack Dataset Augmentation in Web API Detection. Em: 2025 1st International Conference on Consumer Technology (ICCT-Pacific). IEEE, 2025.

2. Palavras-chave
LLM, Generative AI, Data Augmentation, Web API, Intrusion Detection System, Privacy.

3. Objetivo
Propor uma abordagem que utiliza Modelos de Linguagem de Grande Porte (LLMs) para gerar conjuntos de dados sintéticos de ataques a APIs Web, resolvendo a escassez de dados de treinamento realistas e contornando restrições de privacidade que impedem o uso de tráfego de rede real.

4. Metodologia
A pesquisa emprega o API Traffic Research Dataset Framework (ATRDF), que contém 127.500 chamadas de API. Os dados passam por pré-processamento para limpeza e seleção de características, sendo então convertidos em pares estruturados de entrada e saída. Esses pares são utilizados para realizar o ajuste fino (fine-tuning) do modelo fundacional LLaMa. O treinamento utiliza a técnica de Adaptação de Baixo Posto (LoRA) para modificar os parâmetros do modelo com eficiência computacional.

5. Resultados
O desempenho do modelo gerador é medido através de métricas automatizadas de similaridade textual, especificamente os escores BLEU e BERT. O BLEU avalia a sobreposição exata de palavras, enquanto o BERT avalia a similaridade semântica entre as requisições geradas pelo modelo e as respostas de referência do conjunto de testes.

6. Conclusão em relação à pesquisa
Este artigo invalida o uso de LLMs puramente generativos para o escopo principal, pois os autores utilizam a IA offline apenas para criar tráfego falso (Data Augmentation) destinado ao treinamento de outros sistemas. No projeto, podemos citar este documento na revisão de literatura para apontar a obsolescência das bases de dados estáticas. Essa crítica fundamenta a decisão metodológica de usar o Nessus contra o Juice Shop, provando que avaliar a capacidade do LLM de detectar ataques em um ambiente ativo e dinâmico é uma abordagem desejável.

1. Referência Bibliográfica:
MATSUDA, Wataru et al. Enhancing Incident Response Through Sigma MCP and Operational Policy Integration with LLM. Em: 2025 IEEE International Conference on Computing (ICOCO). IEEE, 2025.

2. Palavras-chave:
Sigma Rules, Large Language Model (LLM), False Positive Reduction, Model Context Protocol (MCP), Incident Response.

3. Objetivo:
Propor o Sigma MCP, um método projetado para aprimorar a precisão da resposta a incidentes e reduzir taxas de falsos positivos, combinando a detecção determinística baseada em regras Sigma com a interpretação de políticas operacionais específicas da organização através de um Modelo de Linguagem de Grande Porte (LLM).

4. Metodologia:
O sistema é construído sobre a arquitetura do Model Context Protocol (MCP), separando a operação entre cliente e servidor. Um usuário envia uma requisição em linguagem natural via cliente MCP, que a repassa ao servidor Sigma MCP. O servidor recupera regras Sigma aplicáveis à ameaça, converte-as em consultas do Elasticsearch para extrair logs e, em seguida, injeta políticas operacionais predefinidas (como horários permitidos e IPs de administradores) no contexto do LLM. O experimento avaliou o Sigma MCP contra o Elasticsearch MCP e o Claude Sonnet 4 operando de forma independente, utilizando um ambiente de testes Active Directory. A rede foi alvo de execuções de ferramentas ofensivas reais, incluindo Mimikatz, BloodHound e scripts da suíte Impacket, para testar a precisão e a ocorrência de falsos positivos.

5. Resultados:
O Sigma MCP obteve o melhor desempenho quantitativo, atingindo Precisão de 1.0, Recall de 0.875 e F1-Score de 0.93, sem registrar falsos positivos. O sistema distinguiu com sucesso atividades maliciosas de operações administrativas legítimas (como o uso do PsExec) ao avaliar as ações contra as regras operacionais fornecidas ao LLM. O Elasticsearch MCP registrou um F1-Score inferior de 0.67, gerando falsos positivos ao sinalizar operações normais de manutenção como ameaças. A execução do modelo Claude Sonnet 4 sem a integração MCP fracassou, produzindo consultas inválidas e falhando em detectar verdadeiros positivos.

6. Conclusão em relação à pesquisa:
Este artigo fornece a modelagem arquitetural exata para a Fase 3 e Fase 4 da sua metodologia (Ingestão de Dados e Orquestração da Mitigação). Ele prova que a integração de um LLM direto na base de logs é ineficiente e propensa a erros de sintaxe (como provado pelo fracasso do Claude isolado). A lição prática para o seu experimento com o Juice Shop e Nessus é a adoção do conceito de "Políticas Operacionais" como contexto no prompt. Para manter sua "Taxa de Falsos Positivos" baixa e provar sua hipótese, você não deve enviar apenas os logs puros para o LLM; você deve injetar no prompt um dicionário de regras de negócio definindo o comportamento padrão do Juice Shop, permitindo que a IA anule os alertas falsos de forma autônoma. Além disso, o F1-Score de 0.93 deste estudo é o novo referencial quantitativo que a sua topologia precisará bater.

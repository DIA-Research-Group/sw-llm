import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. CARREGAMENTO E PREPARAÇÃO DOS DADOS
# ==========================================
print("[*] Carregando e mesclando os dados...")
df_gpt = pd.read_csv("resultadosGPR4o-mini.csv")
df_gemini = pd.read_csv("resultadosGEMINI2.5flash.csv")

# Juntar os dataframes
df_completo = pd.concat([df_gpt, df_gemini], ignore_index=True)

# Limpeza: Remover o teste isolado do Gemma para focar na comparação principal
df_clean = df_completo[df_completo['Modelo'] != 'google/gemma-4-31b-it:free'].copy()

# Renomear os modelos para ficar mais elegante nos eixos do gráfico
df_clean['Modelo'] = df_clean['Modelo'].replace({
    'openai/gpt-4o-mini': 'GPT-4o-mini',
    'google/gemini-2.5-flash-lite': 'Gemini 2.5 Flash Lite'
})

# ==========================================
# 2. CONFIGURAÇÃO DE ESTILO ACADÊMICO
# ==========================================
# 'whitegrid' é excelente para artigos científicos pois facilita a leitura
# 'paper' ajusta a proporção das linhas e fontes para impressão
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)

# Paleta de cores amigável para daltônicos e elegante para impressão em PDF
paleta = {"GPT-4o-mini": "#1f77b4", "Gemini 2.5 Flash Lite": "#ff7f0e"}

# ==========================================
# 3. GRÁFICO 1: BOXPLOT DE LATÊNCIA
# ==========================================
print("[*] Gerando Boxplot de Latência...")
plt.figure(figsize=(7, 5))
ax1 = sns.boxplot(x='Modelo', y='Latencia_Segundos', data=df_clean, width=0.4, palette=paleta)

plt.title('Distribuição da Latência de Decisão (IPS)', fontsize=14, pad=15, fontweight='bold')
plt.ylabel('Tempo de Resposta (Segundos)', fontsize=12)
plt.xlabel('Modelo de Linguagem (LLM)', fontsize=12)

# Salvar em alta resolução para o artigo
plt.tight_layout()
plt.savefig('CBSoft_Fig1_Boxplot_Latencia.png', dpi=300)
print("[+] Arquivo 'CBSoft_Fig1_Boxplot_Latencia.png' salvo com sucesso!")
plt.show()

# ==========================================
# 4. GRÁFICO 2: SCATTERPLOT (TOKENS VS LATÊNCIA)
# ==========================================
print("[*] Gerando Scatterplot de Contexto vs Latência...")
plt.figure(figsize=(8, 5))
ax2 = sns.scatterplot(x='Tokens_Totais', y='Latencia_Segundos', hue='Modelo', 
                      data=df_clean, s=80, alpha=0.75, palette=paleta, edgecolor='w')

plt.title('Impacto do Tamanho do Contexto na Latência', fontsize=14, pad=15, fontweight='bold')
plt.ylabel('Tempo de Resposta (Segundos)', fontsize=12)
plt.xlabel('Volume de Contexto Processado (Tokens)', fontsize=12)

# Posicionar a legenda fora do gráfico para não sobrepor os pontos
plt.legend(title='Modelo Avaliado', bbox_to_anchor=(1.05, 1), loc='upper left')

# Salvar em alta resolução (bbox_inches='tight' impede que a legenda seja cortada)
plt.tight_layout()
plt.savefig('CBSoft_Fig2_Scatter_Tokens.png', dpi=300, bbox_inches='tight')
print("[+] Arquivo 'CBSoft_Fig2_Scatter_Tokens.png' salvo com sucesso!")
plt.show()

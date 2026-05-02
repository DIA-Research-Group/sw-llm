import matplotlib.pyplot as plt
import seaborn as sns

# ==========================================
# 1. DADOS DA PROJEÇÃO (10 MINUTOS DE ATAQUE)
# ==========================================
# Projeção: 20.000 logs gerados pelo ZAP. 
# Força Bruta: 20k logs / pacotes de 50 = 400 chamadas. 400 * ~4250 tokens = 1.7M tokens.
# Híbrido: Dados reais do seu CSV do GPT-4o-mini.

cenarios = ['LLM Puro\n(Força Bruta)', 'Híbrido\n(IF + LLM)']
chamadas = [400, 39]  
tokens = [1700000, 166335] 

# ==========================================
# 2. CONFIGURAÇÃO VISUAL
# ==========================================
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 5))

# Vermelho para o cenário ruim (gargalo), Azul para a sua solução
cores = ['#d62728', '#1f77b4']

# ==========================================
# 3. GRÁFICO 1: CHAMADAS À API
# ==========================================
sns.barplot(x=cenarios, y=chamadas, palette=cores, ax=ax1, edgecolor='k')
ax1.set_title('Requisições à API (10 minutos)', fontsize=13, pad=15, fontweight='bold')
ax1.set_ylabel('Total de Chamadas de Rede')

# Colocar os valores exatos em cima das barras
for i, v in enumerate(chamadas):
    ax1.text(i, v + 10, str(v), ha='center', fontweight='bold', fontsize=12)

# ==========================================
# 4. GRÁFICO 2: CONSUMO DE TOKENS
# ==========================================
sns.barplot(x=cenarios, y=tokens, palette=cores, ax=ax2, edgecolor='k')
ax2.set_title('Consumo de Contexto (Tokens)', fontsize=13, pad=15, fontweight='bold')
ax2.set_ylabel('Total de Tokens Consumidos')

# Formatar o eixo Y para k e M (milhares e milhões) para não ficar com números gigantes
ticks_y = ax2.get_yticks()
ax2.set_yticklabels([f'{int(val/1000)}k' if val < 1000000 else f'{val/1000000:.1f}M' for val in ticks_y])

# Colocar os valores exatos formatados em cima das barras
for i, v in enumerate(tokens):
    texto = f"{v/1000:.0f}k" if v < 1000000 else f"{v/1000000:.1f}M"
    ax2.text(i, v + 30000, texto, ha='center', fontweight='bold', fontsize=12)

# ==========================================
# 5. SALVAR E MOSTRAR
# ==========================================
plt.tight_layout()
plt.savefig('CBSoft_Fig3_Eficiencia_Hibrida.png', dpi=300, bbox_inches='tight')
print("[+] Arquivo 'CBSoft_Fig3_Eficiencia_Hibrida.png' gerado com sucesso!")
plt.show()

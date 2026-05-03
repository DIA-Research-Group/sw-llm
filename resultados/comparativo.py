import matplotlib.pyplot as plt
import seaborn as sns

print("[*] Gerando Gráfico de Eficiência Arquitetural (Força Bruta vs Híbrida)...")

# Estilo acadêmico
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)

# Configurando a figura com 2 subplots lado a lado
fig, axes = plt.subplots(1, 2, figsize=(10, 5))

# Dados do seu teste (Força Bruta vs Híbrida)
labels = ['LLM Puro\n(Força Bruta)', 'Arquitetura Híbrida\n(iForest + LLM)']
reqs = [400, 39]
tokens = [1700000, 166335]
cores = ['#d62728', '#1f77b4'] # Vermelho (ruim) vs Azul (bom)

# --- Subplot 1: Requisições à API ---
sns.barplot(x=labels, y=reqs, ax=axes[0], palette=cores, hue=labels, legend=False, edgecolor='.2')
axes[0].set_title('Requisições à API (10 minutos)', fontsize=13, pad=10, fontweight='bold')
axes[0].set_ylabel('Total de Chamadas de Rede', fontsize=12)
axes[0].set_ylim(0, 480) # Respiro no topo

# Textos nas barras (Subplot 1)
for p in axes[0].patches:
    axes[0].annotate(f"{int(p.get_height())}", 
                     (p.get_x() + p.get_width() / 2., p.get_height()), 
                     ha='center', va='bottom', xytext=(0, 5), 
                     textcoords='offset points', fontsize=12, fontweight='bold')

# --- Subplot 2: Consumo de Contexto ---
sns.barplot(x=labels, y=tokens, ax=axes[1], palette=cores, hue=labels, legend=False, edgecolor='.2')
axes[1].set_title('Consumo de Contexto', fontsize=13, pad=10, fontweight='bold')
axes[1].set_ylabel('Total de Tokens Consumidos', fontsize=12)
axes[1].set_ylim(0, 2000000) # Respiro no topo

# Textos formatados nas barras (Subplot 2)
textos_formatados = ['1.7M', '166k']
for p, texto in zip(axes[1].patches, textos_formatados):
    axes[1].annotate(texto, 
                     (p.get_x() + p.get_width() / 2., p.get_height()), 
                     ha='center', va='bottom', xytext=(0, 5), 
                     textcoords='offset points', fontsize=12, fontweight='bold')

plt.tight_layout()
plt.savefig('CBSoft_Fig5_Eficiencia_Hibrida.png', dpi=300)
print("[+] Arquivo 'CBSoft_Fig5_Eficiencia_Hibrida.png' salvo com sucesso!")
plt.show()

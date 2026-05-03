import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# ==========================================
# 1. DATA LOADING AND PREPROCESSING
# ==========================================
print("[*] Loading and consolidating experimental datasets...")

# Define file paths
gpt_data = "resultados/resultadosGPR4o-mini.csv"
gemini_data = "resultados/resultadosGEMINI2.5flash.csv"
current_experiment = "resultados/resultados_pesquisa.csv"

dataframes = []

# Load datasets if they exist
for path in [gpt_data, gemini_data, current_experiment]:
    if os.path.exists(path):
        dataframes.append(pd.read_csv(path))

if not dataframes:
    print("[ERROR] No experimental data found in 'resultados/'. Please run experiments first.")
    exit(1)

# Consolidate data
df_consolidated = pd.concat(dataframes, ignore_index=True)

# Data Cleaning: Filter specific models if necessary and map identifiers to formal names
model_mapping = {
    'openai/gpt-4o-mini': 'GPT-4o-mini',
    'google/gemini-2.5-flash-lite': 'Gemini 2.5 Flash Lite',
    'anthropic/claude-3-5-haiku': 'Claude 3.5 Haiku'
}

df_clean = df_consolidated.copy()
df_clean['Model'] = df_clean['Model'].replace(model_mapping)

# Ensure numeric types
numeric_cols = ['Total_Tokens', 'Latency_Seconds', 'Logs_in_Window']
for col in numeric_cols:
    df_clean[col] = pd.to_numeric(df_clean[col], errors='coerce')

df_clean = df_clean.dropna(subset=numeric_cols)

# ==========================================
# 2. ACADEMIC VISUALIZATION CONFIGURATION
# ==========================================
sns.set_theme(style="whitegrid", context="paper", font_scale=1.2)

color_palette = {
    "GPT-4o-mini": "#1f77b4",
    "Gemini 2.5 Flash Lite": "#ff7f0e",
    "Claude 3.5 Haiku": "#2ca02c"
}

output_dir = "resultados"

# ==========================================
# 3. FIGURE 1: DECISION LATENCY DISTRIBUTION
# ==========================================
print("[*] Generating Figure 1: Decision Latency Boxplot...")
plt.figure(figsize=(8, 5))
ax1 = sns.boxplot(x='Model', y='Latency_Seconds', data=df_clean, width=0.4, palette=color_palette)

plt.title('Distribution of IPS Decision Latency', fontsize=14, pad=15, fontweight='bold')
plt.ylabel('Response Time (Seconds)', fontsize=12)
plt.xlabel('Large Language Model (LLM)', fontsize=12)

plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'Fig1_Decision_Latency.png'), dpi=300)
print("[SUCCESS] Figure 1 saved.")

# ==========================================
# 4. FIGURE 2: CONTEXT VOLUME VS. LATENCY
# ==========================================
print("[*] Generating Figure 2: Context Volume vs. Latency Correlation...")
plt.figure(figsize=(9, 5))
ax2 = sns.scatterplot(x='Total_Tokens', y='Latency_Seconds', hue='Model', 
                      data=df_clean, s=80, alpha=0.75, palette=color_palette, edgecolor='w')

plt.title('Impact of Context Size on Autonomic Latency', fontsize=14, pad=15, fontweight='bold')
plt.ylabel('Response Time (Seconds)', fontsize=12)
plt.xlabel('Processed Context Volume (Tokens)', fontsize=12)

plt.legend(title='Evaluated Model', bbox_to_anchor=(1.05, 1), loc='upper left')

plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'Fig2_Context_Latency_Correlation.png'), dpi=300, bbox_inches='tight')
print("[SUCCESS] Figure 2 saved.")

# ==========================================
# 5. FIGURE 3: TOKEN CONSUMPTION EFFICIENCY
# ==========================================
print("[*] Generating Figure 3: Token Consumption Efficiency...")
df_clean['Tokens_per_Log'] = df_clean['Total_Tokens'] / df_clean['Logs_in_Window']

plt.figure(figsize=(8, 5))
ax3 = sns.barplot(x='Model', y='Tokens_per_Log', data=df_clean, 
                  palette=color_palette, errorbar=None, edgecolor='.2')

plt.title('Mean Token Consumption per Normalized Log Event', fontsize=14, pad=15, fontweight='bold')
plt.ylabel('Tokens Consumed (per Event)', fontsize=12)
plt.xlabel('Large Language Model (LLM)', fontsize=12)

for p in ax3.patches:
    ax3.annotate(f"{int(p.get_height())} tokens", 
                 (p.get_x() + p.get_width() / 2., p.get_height()), 
                 ha='center', va='bottom', 
                 xytext=(0, 5), 
                 textcoords='offset points',
                 fontsize=11, fontweight='bold')

plt.ylim(0, df_clean['Tokens_per_Log'].max() * 1.15)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'Fig3_Token_Efficiency.png'), dpi=300)
print("[SUCCESS] Figure 3 saved.")

# ==========================================
# 6. FIGURE 4: CUMULATIVE DISTRIBUTION FUNCTION (CDF)
# ==========================================
print("[*] Generating Figure 4: Latency CDF...")
plt.figure(figsize=(8, 5))
ax4 = sns.ecdfplot(data=df_clean, x='Latency_Seconds', hue='Model', 
                   palette=color_palette, linewidth=2.5)

plt.title('Cumulative Distribution Function (CDF) of Latency', fontsize=14, pad=15, fontweight='bold')
plt.ylabel('Cumulative Probability', fontsize=12)
plt.xlabel('Response Time (Seconds)', fontsize=12)

plt.axhline(0.9, color='gray', linestyle='--', alpha=0.7)
plt.text(df_clean['Latency_Seconds'].min(), 0.92, '90th Percentile', color='gray', fontsize=10)

plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'Fig4_Latency_CDF.png'), dpi=300)
print("[SUCCESS] Figure 4 saved.")

# Cyber Privacy Shield
Jonas Bonfá Pelegrina

# Como utilizar

1. Abra o Firefox e acesse about:debugging na barra de endereço

2. Clique em "Este Firefox" no menu lateral

3. Clique em "Carregar extensão temporária..."

4. Navegue até a pasta cyber-privacy-shield/ e selecione o arquivo manifest.json

# Usos reais


# Pontuação de Privacidade
A pontuação começa em 100 pontos e recebe penalidades proporcionais a cada ameaça detectada.

Indicador| Penalidade| Máximo| Justificativa
Rastreadores detectados|	-8 por rastreador|-40 Alto impacto no perfil do usuário|

Domínios de terceira parte|	-2 por domínio|-20 Risco de rastreamento indireto|

Cookies de terceira parte|	-4 por cookie|-20 Persistência de identidade cross-site|

Canvas Fingerprinting|	-20|-20	Identificação sem consentimento|

Hook / Hijacking detectado|	-30|-30	Comprometimento ativo do browser|

Scripts suspeitos|-10 por script|-20 Código malicioso potencial|

Supercookies|-5 por supercookie|-15	Rastreamento difícil de remover|

Cookie Sync|-10|-10|Compartilhamento de identidade|

LocalStorage|-1 por chave|-10 Armazenamento persistente não-cookie|

IndexedDB|-5|-5|Base de dados local|


Nota	Pontuação	Avaliação
A	80–100	Excelente – página respeita a privacidade
B	60–79	Bom – rastreamento mínimo
C	40–59	Regular – rastreamento moderado
D	20–39	Ruim – rastreamento intenso
F	0–19	Péssimo – múltiplas ameaças detectadas

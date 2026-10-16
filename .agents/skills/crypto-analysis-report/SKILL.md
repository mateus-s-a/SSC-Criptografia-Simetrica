---
name: crypto-analysis-report
description: >-
  Use esta skill para calcular e gerar automaticamente todos os registros
  hexadecimais da Etapa 3 (chave, PKCS#7, 5 estados intermediários da rodada 1,
  efeito avalanche) com os dados reais da dupla (Mateus e Lorena) e elaborar
  o relatório técnico final de até 4 páginas sobre o modo ECB.
---

# Skill: Crypto Analysis & Technical Report Generator

Esta habilidade gerencia a extração analítica de dados matemáticos do AES-128 para os dados reais da dupla e a estruturação do relatório acadêmico de até 4 páginas.

## Status de Elaboração
- **Decisão em Aberto**: A dupla (Mateus e Lorena) está definindo a dinâmica e o formato exato em que irão elaborar o relatório final (até 4 páginas).
- Esta skill atua como gerador dos dados matemáticos brutos, tabelas formatadas e base teórica para alimentar o documento quando decidirem o formato.

## Responsabilidades
1. **Geração Automática dos Registros da Etapa 3**:
   - Executar o script [generate_analysis_data.py](./scripts/generate_analysis_data.py) fornecendo as matrículas de Mateus e Lorena.
   - O script gera:
     - Chave em ASCII e Hexadecimal.
     - Mensagem original e blocos formatados com PKCS#7.
     - Texto cifrado final.
     - Chaves de rodada 0 ($W[0..3]$) e 1 ($W[4..7]$).
     - Os 5 estados intermediários do Bloco 1 na Rodada 1:
       1. Após `AddRoundKey` inicial (Chave 0).
       2. Após `SubBytes`.
       3. Após `ShiftRows`.
       4. Após `MixColumns`.
       5. Após `AddRoundKey` (Chave 1).
     - Teste de Efeito Avalanche: inversão de 1 bit na chave e na mensagem, com cálculo da distância de Hamming e porcentagem de alteração esperada (~50%).
2. **Estrutura do Relatório de até 4 Páginas**:
   - **Página 1**: Identificação da dupla (Mateus e Lorena), objetivo, formulação das matrículas, chave e mensagem.
   - **Página 2**: Registros da Etapa 3 e apresentação minuciosa dos 5 estados da Rodada 1.
   - **Página 3**: Análise experimental do Efeito Avalanche (tabelas e gráficos conceituais de dispersão de bits).
   - **Página 4**: Discussão sobre a insegurança do modo ECB, análise de tráfego na UART (exemplo dos comandos `"LIGAR LED VERDE."` e `"DESLIGAR LED    "`), suscetibilidade a replay/adulteração e propostas de modos seguros (CBC/CTR com IV e GCM autenticado).

Consulte o documento de argumentação teórica em [ecb_vulnerabilities.md](./references/ecb_vulnerabilities.md).

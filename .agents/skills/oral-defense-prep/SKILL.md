---
name: oral-defense-prep
description: >-
  Use esta skill para treinar e preparar a dupla (Mateus e Lorena) para a
  apresentação oral e a arguição prática ao vivo perante o professor, cobrindo
  a dinâmica de explicação cruzada de código, fundamentação matemática do AES e
  resolução de desafios em tempo real.
---

# Skill: Oral Defense & Live Arguição Preparation

Esta habilidade estrutura a preparação técnica da dupla Mateus e Lorena para a apresentação oral e a avaliação prática em bancada com o professor.

## Dinâmica da Avaliação
1. **Demonstração em Bancada**:
   - Conectar os dois ESP32 via UART2 (TX-RX cruzado e GND comum).
   - Abrir o Monitor Serial USB da Placa B a 115200 bps.
   - Enviar a mensagem da dupla a partir da Placa A e exibir o texto decifrado na Placa B.
2. **Explicação Cruzada (Cross-Explanation)**:
   - **Mateus** (autor do TX) explicará trechos do código do **Receptor (RX)** implementado por **Lorena** (leitura do marcador `0xAA`, temporização de timeout, decifragem AES inversa e remoção do preenchimento PKCS#7).
   - **Lorena** (autora do RX) explicará trechos do código do **Transmissor (TX)** implementado por **Mateus** (derivação da chave pelas matrículas, padding PKCS#7, empacotamento do quadro binário `[0xAA, n, payload]` e cifragem AES).
   - Ambos devem conhecer integralmente cada função primitiva do AES (`SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`, `KeyExpansion`).
3. **Desafio ao Vivo (Live Modification)**:
   - Na hora da avaliação, o professor pedirá uma modificação imediata (ex: cifrar uma mensagem customizada ou inverter um bit na chave).
   - A dupla possui o trunfo de poder responder instantaneamente pelo **Console Interativo USB do `transmissor.ino`** (basta digitar a nova mensagem ditada pelo professor no Monitor Serial, ou usar `/flip` para inverter 1 bit da chave), bem como saber alterar diretamente as variáveis do código-fonte e recompilar/gravar se solicitado.
4. **Defesa Conceitual**:
   - Explicar a origem matemática da S-Box ($GF(2^8)$ e transformação afim).
   - Explicar o que é e como funciona o `xtime`.
   - Responder por que o modo ECB é vulnerável e o que o espião na UART aprende.

Consulte o banco de questões esperadas em [qna_professor_defense.md](./references/qna_professor_defense.md).

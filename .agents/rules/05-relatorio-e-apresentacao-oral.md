# Regras do Relatório Técnico e Apresentação Oral

## 1. Requisitos do Relatório Técnico
- **Limite de Páginas**: Máximo de **4 páginas**.
- **Seções Mandatórias**:
  1. **Registros Hexadecimais da Dupla**:
     - Chave de 16 bytes derivada das matrículas de Mateus e Lorena.
     - Mensagem original formatada e mensagem após preenchimento PKCS#7.
     - Texto cifrado final resultante da cifragem ECB.
     - Chaves de rodada geradas pela expansão: Rodada 0 ($W[0..3]$) e Rodada 1 ($W[4..7]$).
  2. **Cinco Estados Intermediários do Bloco 1 na Rodada 1**:
     - Estado 1: Após `AddRoundKey` inicial (com Chave 0 - Whitening).
     - Estado 2: Após `SubBytes`.
     - Estado 3: Após `ShiftRows`.
     - Estado 4: Após `MixColumns`.
     - Estado 5: Após `AddRoundKey` (com Chave 1).
  3. **Análise do Efeito Avalanche**:
     - Procedimento: Inverter exatamente 1 bit na chave ou na mensagem.
     - Medição: Contagem de bits divergentes (distância de Hamming) no bloco cifrado resultante de 128 bits.
     - Resultado Teórico Esperado: $\approx 50\%$ ($\approx 64$ bits alterados).
  4. **Discussão Crítica sobre o Modo ECB**:
     - Explicação prática da vulnerabilidade com o exemplo de 3 blocos:
       - Bloco 1: `"LIGAR LED VERDE."` $\to$ `e0c22a6f02664f487dc9528642203dec`
       - Bloco 2: `"DESLIGAR LED    "` $\to$ `2b4d065ea65478b60696616244cd5070`
       - Bloco 3: `"LIGAR LED VERDE."` $\to$ `e0c22a6f02664f487dc9528642203dec`
     - Detalhamento do que um espião na UART deduz (padrões e frequência de comandos).
     - Como um atacante pode adulterar o fluxo sem decifrar (reordenação, substituição ou replay de blocos).
     - Modos modernos seguros recomendados: CBC (Cipher Block Chaining) ou CTR (Counter Mode) com IV aleatório por mensagem, ou GCM (Galois/Counter Mode) para confidencialidade e integridade autenticada.

---

## 2. Dinâmica da Apresentação Oral e Arguição
- **Demonstração em Bancada**: Os dois ESP32 devem estar conectados via UART2 e demonstrar o envio e decifragem de mensagens em tempo real.
- **Explicação Cruzada Obrigatória**:
  - **Mateus** (que codificou o TX) deverá explicar trechos do código do **Receptor (RX)** implementado por **Lorena** (máquina de estados da UART, recepção com timeout, AES Decrypt inverso e descarte de PKCS#7).
  - **Lorena** (que codificou o RX) deverá explicar trechos do código do **Transmissor (TX)** implementado por **Mateus** (preenchimento PKCS#7, empacotamento do frame `[0xAA, n, blocos]`, `Serial2.write` de bytes brutos e AES Encrypt).
  - Ambos devem dominar cada transformação matemática do AES (`SubBytes`, `MixColumns`, `ShiftRows`, `xtime`, `KeyExpansion`).
- **Desafio em Tempo Real pelo Professor**:
  - Na hora da arguição, o professor proporá uma alteração (ex: cifrar uma mensagem nova ditada na hora ou inverter 1 bit na chave).
  - A dupla deverá aplicar a modificação, compilar/enviar ou reconfigurar, e explicar o resultado obtido.
  - O resultado será confrontado imediatamente com o código de referência do professor.

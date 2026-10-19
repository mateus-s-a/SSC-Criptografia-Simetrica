---
name: esp32-firmware-uart
description: >-
  Use esta skill para desenvolver, configurar e depurar os códigos-fonte C/C++
  dos dois ESP32 (Transmissor A e Receptor B), gerenciando a comunicação UART2
  a 115200 bps 8N1, o envio do protocolo em bytes binários brutos e a recepção com timeout.
---

# Skill: ESP32 Firmware & UART Protocol

Esta habilidade orienta o desenvolvimento do firmware embarcado para as duas placas ESP32 interligadas fisicamente via UART2.

## Divisão de Desenvolvimento
- **Mateus**: Responsável primário pelo **Transmissor (`transmissor.ino` na raiz)** (Placa A).
- **Lorena**: Responsável primária pelo **Receptor (`receptor.ino` na raiz)** (Placa B).

## Responsabilidades
1. **Estrutura de Firmware para Arduino IDE (Arquivo Único `.ino`)**:
   - `transmissor.ino` (Placa A - Mateus): 
     - **Modo Automático**: Ao ligar, deriva a chave (`7844002878440030`), monta a mensagem oficial (`A:2023278440028;B:2023278440030`), aplica PKCS#7 e envia via `Serial2.write`.
     - **Console Interativo USB (`Serial`)**: Escuta entradas via Monitor Serial. Qualquer texto digitado é preenchido dinamicamente com PKCS#7, cifrado e enviado pela UART2. Suporta comandos `/test` (autoteste dos vetores FIPS-197), `/flip` (inverter 1 bit da chave), `/key <nova_chave>` e `/reset`. As rotinas de validação do FIPS-197 permanecem no firmware para a demonstração oral.
   - `receptor.ino` (Placa B - Lorena): Contém todas as constantes, funções do AES-128 inverso e rotinas de recepção no sketch `.ino`, sincronizando em `0xAA`, recebendo bytes brutos com timeout, decifrando, removendo PKCS#7 e exibindo no Serial Monitor USB (`Serial`).
2. **Configuração Fisiológica da UART2**:
   - Pinagem recomendada:
     - Placa A TX2 (GPIO 17) $\to$ Placa B RX2 (GPIO 16)
     - Placa A RX2 (GPIO 16) $\to$ Placa B TX2 (GPIO 17)
     - GND $\leftrightarrow$ GND (obrigatório para referência comum de potencial).
   - Inicialização em C/Arduino:
     ```cpp
     Serial2.begin(115200, SERIAL_8N1, 16, 17); // RX, TX
     ```
3. **Formatação e Envio do Pacote (Placa A)**:
   - Proibido usar texto hexadecimal na UART2.
   - Enviar byte a byte:
     1. Marcador fixo: `0xAA` (1 byte).
     2. Número de blocos $n$: `(uint8_t)n_blocks` (1 byte).
     3. Blocos cifrados: buffer de $16 \times n$ bytes brutos via `Serial2.write(buffer, 16 * n)`.
4. **Máquina de Estados de Recepção com Timeout (Placa B)**:
   - Estado 0: Aguarda `Serial2.available()`. Descarta bytes até ler `0xAA`.
   - Estado 1: Lê 1 byte correspondente ao número de blocos $n$.
   - Estado 2: Lê exatamente $16 \times n$ bytes armazenando em buffer.
     - Implementar `uint32_t start_ms = millis()` com limite (ex: 2000 ms). Se o timeout expirar antes de receber todos os bytes, abortar a leitura e voltar ao Estado 0.
   - Estado 3: Executa decifragem bloco a bloco (AES-128 ECB Decrypt).
   - Estado 4: Valida e descarta o preenchimento PKCS#7.
   - Estado 5: Imprime a string decifrada em `Serial.println()` (USB / UART0).

Consulte [uart_packet_specs.md](./references/uart_packet_specs.md) para detalhes de temporização e especificação do frame.

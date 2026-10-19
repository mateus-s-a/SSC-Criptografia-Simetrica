# Regras da Comunicação UART e Protocolo entre ESP32

## 1. Topologia e Parâmetros da UART
- **Interface Fisiológica**: UART2 por hardware nos microcontroladores ESP32.
- **Pinagem Padrão ESP32**:
  - Placa A TX2 (ex: GPIO 17) $\to$ Placa B RX2 (ex: GPIO 16)
  - Placa A RX2 (ex: GPIO 16) $\to$ Placa B TX2 (ex: GPIO 17)
  - GND da Placa A interligado obrigatoriamente ao GND da Placa B (referência de potencial comum).
- **Parâmetros Seriais**:
  - Baudrate: `115200 bps`
  - Configuração: `8N1` (8 bits de dados, sem paridade, 1 stop bit).

---

## 2. Estrutura do Quadro de Transmissão (Frame de Protocolo)
- **Regra Fundamental**: A transmissão deve ser feita em **bytes binários brutos** (`write`), **JAMAIS** como caracteres ASCII de texto hexadecimal (não usar `print("%02X")` na UART2).
- Composição do Frame:

| Campo | Tamanho | Valor / Descrição |
| :--- | :--- | :--- |
| **Marcador de Início** | 1 byte | Valor fixo `0xAA` |
| **Nº de Blocos ($n$)** | 1 byte | Quantidade inteira de blocos AES ($n \ge 1$) |
| **Carga Cifrada** | $16 \times n$ bytes | Bytes brutos dos blocos cifrados consecutivos |

*Tamanho total do frame*: $2 + 16 \times n$ bytes.

---

## 3. Console Interativo USB no Transmissor (Placa A)
- **Porta USB Serial (`Serial`)**: Opera a 115200 bps.
- **Funcionamento**:
  - No boot (`setup()`): transmite imediatamente o pacote oficial da dupla.
  - No `loop()`: escuta strings enviadas via teclado no Monitor Serial.
  - Ao receber qualquer nova linha:
    1. Calcula o preenchimento PKCS#7 dinâmico para a nova string.
    2. Cifra em blocos AES-128 ECB.
    3. Monta e transmite o quadro binário via `Serial2.write`.
    4. Imprime no Monitor Serial local o dump hexadecimal dos blocos para conferência.
  - Comandos de controle suportados:
    - `/test`: reexecuta os autotestes de validação dos vetores NIST FIPS-197 (Apêndices B e C.1) para demonstração ao vivo.
    - `/flip`: inverte 1 bit na chave simétrica atual (`key[0] ^= 0x01`) e reenvia.
    - `/key <nova_chave>`: carrega uma nova chave de 16 bytes.
    - `/reset`: restaura a chave original da dupla.

---

## 4. Máquina de Estados e Recepção na Placa B
1. **Sincronização**: O receptor lê continuamente a UART2 até detectar o marcador `0xAA`.
2. **Leitura do Cabeçalho**: Lê o byte seguinte representando $n$ (número de blocos).
3. **Leitura dos Dados com Timeout**:
   - Lê exatamente $16 \times n$ bytes.
   - Deve implementar tempo limite de recepção (*timeout*) para evitar travamento em caso de perda ou ruído no canal.
4. **Decifragem e Pós-Processamento**:
   - Decifra cada bloco de 16 bytes usando a função AES-128 Decrypt.
   - Valida e descarta o preenchimento PKCS#7.
   - Envia a mensagem decifrada em texto claro para o Monitor Serial principal (USB / UART0) a 115200 bps.

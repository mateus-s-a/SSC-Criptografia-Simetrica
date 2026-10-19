# Especificação do Protocolo Binário de UART2

## 1. Diagrama do Quadro de Transmissão

```text
+----------------+-------------------+--------------------+ ... +--------------------+
| Marcador 0xAA  |  Nº Blocos (n)    |  Bloco Cifrado 1   | ... |  Bloco Cifrado n   |
|   (1 byte)     |     (1 byte)      |     (16 bytes)     | ... |     (16 bytes)     |
+----------------+-------------------+--------------------+ ... +--------------------+
|<----------------------- Tamanho Total: 2 + 16*n bytes ------------------------------>|
```

### Exemplo do Enunciado ($n = 2$, 34 bytes no total):
- Byte 0: `0xAA`
- Byte 1: `0x02`
- Bytes 2 a 17: `3a 37 84 99 1a b0 ac aa 88 d5 fd 94 cb 7b 74 ad`
- Bytes 18 a 33: `cb ea 1d 9e 3e 1f 39 da 47 11 1c f6 90 64 b1 66`

---

## 2. Lógica de Timeout e Desserialização Robusta em C++

```cpp
bool receive_packet(HardwareSerial &uart, uint8_t *out_buffer, uint8_t &out_blocks, uint32_t timeout_ms) {
    uint32_t start_time = millis();
    
    // 1. Sincronizar no marcador 0xAA
    while (true) {
        if (uart.available()) {
            uint8_t sync = uart.read();
            if (sync == 0xAA) break;
        }
        if (millis() - start_time > timeout_ms) return false;
    }

    // 2. Ler número de blocos
    while (!uart.available()) {
        if (millis() - start_time > timeout_ms) return false;
    }
    out_blocks = uart.read();
    if (out_blocks == 0 || out_blocks > 16) return false; // sanidade

    uint16_t expected_bytes = out_blocks * 16;
    uint16_t received = 0;

    // 3. Ler blocos cifrados
    while (received < expected_bytes) {
        if (uart.available()) {
            out_buffer[received++] = uart.read();
        }
        if (millis() - start_time > timeout_ms) return false; // timeout
    }

    return true;
}
```

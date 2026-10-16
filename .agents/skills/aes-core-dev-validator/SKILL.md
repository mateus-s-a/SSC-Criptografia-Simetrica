---
name: aes-core-dev-validator
description: >-
  Use esta skill para desenvolver, modularizar, testar e validar o algoritmo
  AES-128 em C/C++ do zero (sem bibliotecas externas criptográficas),
  garantindo conformidade com os vetores de teste oficiais do NIST FIPS-197
  (Apêndice B e Apêndice C.1) e do enunciado do professor.
---

# Skill: AES-128 Core Developer & Validator

Esta habilidade orienta a implementação e verificação estrita do núcleo criptográfico AES-128 em linguagem C/C++ compatível com o ambiente ESP32 (Arduino / ESP-IDF / PlatformIO).

## Responsabilidades
1. **Estrutura de Arquivos em C/Arduino**:
   - As funções e tabelas do AES-128 são integradas diretamente dentro de cada sketch `.ino` na raiz (`transmissor.ino` e `receptor.ino`), mantendo cada firmware autocontido e fácil de depurar e apresentar.
2. **Implementação de Primitivas Obrigatórias**:
   - `SubBytes` e `InvSubBytes` (usando LUTs na memória flash com `PROGMEM`).
   - `ShiftRows` e `InvShiftRows`.
   - `MixColumns` e `InvMixColumns` (usando a função `xtime`).
   - `AddRoundKey` (operação XOR).
   - `KeyExpansion` (10 rodadas gerando $44 \times 32$-bit words / 176 bytes / 11 chaves de rodada).
3. **Validação com Vetores de Teste**:
   - Executar o script de teste [verify_aes_fips.py](./scripts/verify_aes_fips.py) para conferir a matemática e os vetores de teste.
   - Consultar os vetores do NIST em [fips197_vectors.md](./references/fips197_vectors.md).

## Procedimento de Validação Passo a Passo
1. Implementar a operação elementar `xtime`:
   ```c
   uint8_t xtime(uint8_t b) {
       return ((b << 1) ^ (((b >> 7) & 1) * 0x1b));
   }
   ```
2. Validar a multiplicação no corpo finito $GF(2^8)$ para `MixColumns`:
   - Multiplicação por 2: `xtime(b)`
   - Multiplicação por 3: `xtime(b) ^ b`
   - Multiplicação para `InvMixColumns`:
     - $\times 9$: `xtime(xtime(xtime(b))) ^ b`
     - $\times 11$: `xtime(xtime(xtime(b)) ^ b) ^ b`
     - $\times 13$: `xtime(xtime(xtime(b) ^ b)) ^ b`
     - $\times 14$: `xtime(xtime(xtime(b) ^ b) ^ b)`
3. Validar primeiramente contra o **Apêndice B do FIPS-197**:
   - Chave: `2b7e151628aed2a6abf7158809cf4f3c`
   - Claro: `3243f6a8885a308d313198a2e0370734`
   - Esperado: `3925841d02dc09fbdc118597196a0b32`
4. Validar contra o **Apêndice C.1 do FIPS-197**:
   - Chave: `000102030405060708090a0b0c0d0e0f`
   - Claro: `00112233445566778899aabbccddeeff`
   - Esperado: `69c4e0d86a7b0430d8cdb78070b4c55a`
5. Testar a decifragem com ambos os vetores e garantir reversibilidade perfeita (`Dec(Enc(M)) == M`).

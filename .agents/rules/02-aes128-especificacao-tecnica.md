# Especificação Técnica do AES-128 "Do Zero"

## 1. Funções Primitivas Obrigatórias
O algoritmo AES-128 cifra blocos de 128 bits (16 bytes) usando uma chave de 128 bits (16 bytes) ao longo de 10 rodadas. O código em C/C++ deve implementar explicitamente:

### Cifragem (Encryption):
- `KeyExpansion`: Gera 11 subchaves de 16 bytes ($W[0 \dots 43]$ de 32 bits, correspondendo às rodadas $0 \dots 10$).
- `AddRoundKey`: Realiza a operação XOR bit a bit entre o estado de 16 bytes e a chave da rodada atual.
- `SubBytes`: Substituição não linear de cada byte da matriz de estado usando a S-Box.
- `ShiftRows`: Deslocamento cíclico para a esquerda das linhas da matriz de estado (Linha 0: 0 bytes, Linha 1: 1 byte, Linha 2: 2 bytes, Linha 3: 3 bytes).
- `MixColumns`: Transformação linear que multiplica cada coluna do estado por um polinômio fixo sobre o corpo finito $GF(2^8)$. Deve ser implementada utilizando a função auxiliar `xtime`.
- *Estrutura das rodadas*:
  - Rodada 0 (Whitening inicial): apenas `AddRoundKey(chave 0)`.
  - Rodadas 1 a 9: `SubBytes` -> `ShiftRows` -> `MixColumns` -> `AddRoundKey(chave r)`.
  - Rodada 10 (Final): `SubBytes` -> `ShiftRows` -> `AddRoundKey(chave 10)` (sem `MixColumns`).

### Decifragem (Decryption):
- `InvSubBytes`: Substituição inversa usando a InvS-Box.
- `InvShiftRows`: Deslocamento cíclico inverso para a direita (Linha 1: 3 bytes dir ou 1 byte esq; Linha 2: 2 bytes; Linha 3: 1 byte dir ou 3 bytes esq).
- `InvMixColumns`: Multiplicação das colunas pelo polinômio inverso no corpo $GF(2^8)$ (pesos `{0e}`, `{0b}`, `{0d}`, `{09}`).
- *Estrutura das rodadas inversas*:
  - Rodada inicial inversa: `AddRoundKey(chave 10)`.
  - Rodadas 9 a 1: `InvShiftRows` -> `InvSubBytes` -> `AddRoundKey(chave r)` -> `InvMixColumns`.
  - Rodada 0: `InvShiftRows` -> `InvSubBytes` -> `AddRoundKey(chave 0)`.

---

## 2. Requisitos Matemáticos: S-Box e Corpo Finito $GF(2^8)$
1. **Origem da S-Box**:
   - A S-Box e a InvS-Box podem ser implementadas via tabelas pré-computadas (Lookup Tables - LUT) de 256 bytes na memória flash (`PROGMEM` no ESP32).
   - **Exigência do Professor**: A dupla deve dominar a fundamentação matemática da S-Box:
     1. Inversão multiplicativa no corpo de Galois $GF(2^8)$ com polinômio redutor irredutível $m(x) = x^8 + x^4 + x^3 + x + 1$ (representado pelo byte `0x11B`), com a convenção de que $0^{-1} = 0$.
     2. Aplicação de uma transformação afim invertível sobre $GF(2)$ com vetor constante `0x63`.
2. **Multiplicação em $GF(2^8)$ e Operação `xtime`**:
   - A multiplicação por 2 no polinômio base $x$ é dada pela macro/função `xtime(b)`:
     - `((b << 1) ^ (((b >> 7) & 1) * 0x1B)) & 0xFF`
   - Toda a multiplicação por coeficientes `{02}` e `{03}` em `MixColumns`, bem como `{0e}`, `{0b}`, `{0d}`, `{09}` em `InvMixColumns`, deve ser decomposta em combinações de `xtime` e XORs.

---

## 3. Validação Prévia Mandatória (NIST FIPS-197)
Antes de testar com os dados da dupla, o algoritmo deve ser validado pelos vetores oficiais do NIST FIPS-197:

- **Apêndice B**:
  - Chave: `2b7e151628aed2a6abf7158809cf4f3c`
  - Bloco em Claro: `3243f6a8885a308d313198a2e0370734`
  - Cifrado Esperado: `3925841d02dc09fbdc118597196a0b32`

- **Apêndice C.1**:
  - Chave: `000102030405060708090a0b0c0d0e0f`
  - Bloco em Claro: `00112233445566778899aabbccddeeff`
  - Cifrado Esperado: `69c4e0d86a7b0430d8cdb78070b4c55a`

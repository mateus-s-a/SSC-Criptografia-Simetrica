# Referência de Vetores FIPS-197 e Tabelas AES

## 1. Vetores Oficiais NIST FIPS PUB 197

### Apêndice B — Cipher Example
- **Tamanho da Chave**: 128 bits (16 bytes)
- **Chave (Hex)**: `2b7e151628aed2a6abf7158809cf4f3c`
- **Texto em Claro (Hex)**: `3243f6a8885a308d313198a2e0370734`
- **Texto Cifrado Esperado (Hex)**: `3925841d02dc09fbdc118597196a0b32`

### Apêndice C.1 — AES-128 (Key and Plaintext Sequence)
- **Chave (Hex)**: `000102030405060708090a0b0c0d0e0f`
- **Texto em Claro (Hex)**: `00112233445566778899aabbccddeeff`
- **Texto Cifrado Esperado (Hex)**: `69c4e0d86a7b0430d8cdb78070b4c55a`

---

## 2. Vetores do Enunciado do Professor

### Dados de Exemplo (Matrículas Fictícias $A = 20231001, B = 20231002$)
- **Chave (ASCII)**: `2023100120231002`
- **Chave (Hex)**: `32303233313030313230323331303032`
- **Mensagem Claro (21 bytes)**: `A:20231001;B:20231002`
- **Com PKCS#7 (32 bytes)**:
  - Bloco 1: `413a32303233313030313b423a323032`
  - Bloco 2: `33313030320b0b0b0b0b0b0b0b0b0b0b`
- **Cifrado Final**:
  - Bloco 1: `3a3784991ab0acaa88d5fd94cb7b74ad`
  - Bloco 2: `cbea1d9e3e1f39da47111cf69064b166`

### Exemplo dos Três Blocos ECB (Questão da Apresentação)
- **Chave**: `32303233313030313230323331303032`
- Bloco 1: `"LIGAR LED VERDE."` $\to$ `e0c22a6f02664f487dc9528642203dec`
- Bloco 2: `"DESLIGAR LED    "` $\to$ `2b4d065ea65478b60696616244cd5070`
- Bloco 3: `"LIGAR LED VERDE."` $\to$ `e0c22a6f02664f487dc9528642203dec`

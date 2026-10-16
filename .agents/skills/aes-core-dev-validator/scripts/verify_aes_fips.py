#!/usr/bin/env python3
"""
verify_aes_fips.py
Implementação de referência pura em Python do AES-128 (FIPS-197)
e validador automático dos vetores de teste do enunciado do professor.
"""

# S-Box e Inv S-Box
SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

def xtime(b):
    return ((b << 1) ^ (0x1b if (b & 0x80) else 0x00)) & 0xff

def multiply(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xff
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def key_expansion(key_bytes):
    w = []
    for i in range(4):
        w.append([key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3]])
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // 4]
        word = [w[i - 4][j] ^ temp[j] for j in range(4)]
        w.append(word)
    return w

def add_round_key(state, round_key):
    for c in range(4):
        for r in range(4):
            state[r][c] ^= round_key[c][r]

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def inv_sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = INV_SBOX[state[r][c]]

def shift_rows(state):
    state[1] = state[1][1:] + state[1][:1]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][3:] + state[3][:3]

def inv_shift_rows(state):
    state[1] = state[1][3:] + state[1][:3]
    state[2] = state[2][2:] + state[2][:2]
    state[3] = state[3][1:] + state[3][:1]

def mix_columns(state):
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3
        state[1][c] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3
        state[2][c] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3)
        state[3][c] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3)

def inv_mix_columns(state):
    for c in range(4):
        s0, s1, s2, s3 = state[0][c], state[1][c], state[2][c], state[3][c]
        state[0][c] = multiply(0x0e, s0) ^ multiply(0x0b, s1) ^ multiply(0x0d, s2) ^ multiply(0x09, s3)
        state[1][c] = multiply(0x09, s0) ^ multiply(0x0e, s1) ^ multiply(0x0b, s2) ^ multiply(0x0d, s3)
        state[2][c] = multiply(0x0d, s0) ^ multiply(0x09, s1) ^ multiply(0x0e, s2) ^ multiply(0x0b, s3)
        state[3][c] = multiply(0x0b, s0) ^ multiply(0x0d, s1) ^ multiply(0x09, s2) ^ multiply(0x0e, s3)

def bytes_to_state(b):
    # AES organiza a matriz coluna por coluna
    return [[b[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(state):
    res = bytearray(16)
    for c in range(4):
        for r in range(4):
            res[r + 4*c] = state[r][c]
    return bytes(res)

def aes_encrypt_block(block16, key16):
    w = key_expansion(key16)
    state = bytes_to_state(block16)
    add_round_key(state, w[0:4])
    for rnd in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, w[4*rnd : 4*(rnd+1)])
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, w[40:44])
    return state_to_bytes(state)

def aes_decrypt_block(block16, key16):
    w = key_expansion(key16)
    state = bytes_to_state(block16)
    add_round_key(state, w[40:44])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    for rnd in range(9, 0, -1):
        add_round_key(state, w[4*rnd : 4*(rnd+1)])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
    add_round_key(state, w[0:4])
    return state_to_bytes(state)

def run_tests():
    print("=== Iniciando Verificação do AES-128 ===")
    
    # Teste 1: FIPS-197 Apêndice B
    key_b = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plain_b = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    expected_b = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    cipher_b = aes_encrypt_block(plain_b, key_b)
    decrypted_b = aes_decrypt_block(cipher_b, key_b)
    assert cipher_b == expected_b, f"FIPS B Falhou: {cipher_b.hex()} != {expected_b.hex()}"
    assert decrypted_b == plain_b, "FIPS B Decriptação Falhou"
    print("[OK] NIST FIPS-197 Apêndice B validado com sucesso!")

    # Teste 2: FIPS-197 Apêndice C.1
    key_c = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plain_c = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_c = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    cipher_c = aes_encrypt_block(plain_c, key_c)
    decrypted_c = aes_decrypt_block(cipher_c, key_c)
    assert cipher_c == expected_c, f"FIPS C.1 Falhou: {cipher_c.hex()} != {expected_c.hex()}"
    assert decrypted_c == plain_c, "FIPS C.1 Decriptação Falhou"
    print("[OK] NIST FIPS-197 Apêndice C.1 validado com sucesso!")

    # Teste 3: Exemplo fictício do Enunciado
    key_mock = "2023100120231002".encode('ascii')
    assert key_mock.hex() == "32303233313030313230323331303032"
    b1_plain = bytes.fromhex("413a32303233313030313b423a323032")
    b2_plain = bytes.fromhex("33313030320b0b0b0b0b0b0b0b0b0b0b")
    c1_expected = bytes.fromhex("3a3784991ab0acaa88d5fd94cb7b74ad")
    c2_expected = bytes.fromhex("cbea1d9e3e1f39da47111cf69064b166")
    c1 = aes_encrypt_block(b1_plain, key_mock)
    c2 = aes_encrypt_block(b2_plain, key_mock)
    assert c1 == c1_expected, f"Exemplo Bloco 1 Falhou: {c1.hex()} != {c1_expected.hex()}"
    assert c2 == c2_expected, f"Exemplo Bloco 2 Falhou: {c2.hex()} != {c2_expected.hex()}"
    print("[OK] Exemplo de Matrículas Fictícias validado com sucesso!")

    # Teste 4: Exemplo dos 3 blocos ECB do Enunciado
    m1 = "LIGAR LED VERDE.".encode('ascii')
    m2 = "DESLIGAR LED    ".encode('ascii')
    m3 = "LIGAR LED VERDE.".encode('ascii')
    c1_ecb = aes_encrypt_block(m1, key_mock)
    c2_ecb = aes_encrypt_block(m2, key_mock)
    c3_ecb = aes_encrypt_block(m3, key_mock)
    assert c1_ecb == bytes.fromhex("e0c22a6f02664f487dc9528642203dec")
    assert c2_ecb == bytes.fromhex("2b4d065ea65478b60696616244cd5070")
    assert c3_ecb == bytes.fromhex("e0c22a6f02664f487dc9528642203dec")
    print("[OK] Exemplo dos 3 blocos ECB validado com sucesso!")
    print("\nTODOS OS VETORES DO ENUNCIADO FORAM VALIDADOS COM 100% DE SUCESSO!")

if __name__ == "__main__":
    run_tests()

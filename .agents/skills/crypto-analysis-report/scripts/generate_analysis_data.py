#!/usr/bin/env python3
"""
generate_analysis_data.py
Gera os registros da Etapa 3 do trabalho prático de SSC (AES-128 em ESP32):
- Derivação de Chave a partir das matrículas de Mateus e Lorena
- Formatação de Mensagem e Preenchimento PKCS#7
- Cifragem em Blocos ECB
- Chaves de Rodada 0 e 1
- Os 5 Estados Intermediários do Bloco 1 na Rodada 1
- Teste de Efeito Avalanche com contagem de bits (Distância de Hamming)
"""

import sys
import os
import argparse

# Importa a engine de referência
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../aes-core-dev-validator/scripts')))
try:
    from verify_aes_fips import (
        key_expansion, bytes_to_state, state_to_bytes,
        add_round_key, sub_bytes, shift_rows, mix_columns,
        aes_encrypt_block, aes_decrypt_block
    )
except ImportError:
    print("Erro ao importar engine de aes-core-dev-validator")
    sys.exit(1)

def derive_key(mat_a, mat_b):
    digits_a = ''.join(c for c in mat_a if c.isdigit())[-8:].zfill(8)
    digits_b = ''.join(c for c in mat_b if c.isdigit())[-8:].zfill(8)
    key_ascii = digits_a + digits_b
    key_bytes = key_ascii.encode('ascii')
    return key_ascii, key_bytes

def apply_pkcs7(data_bytes):
    pad_len = 16 - (len(data_bytes) % 16)
    if pad_len == 0:
        pad_len = 16
    return data_bytes + bytes([pad_len] * pad_len)

def count_bits_different(b1, b2):
    diff = 0
    for byte1, byte2 in zip(b1, b2):
        diff += bin(byte1 ^ byte2).count('1')
    return diff

def analyze(mat_a, mat_b):
    print("=" * 70)
    print("       RELATÓRIO DE ANÁLISE CRIPTOGRÁFICA - ETAPA 3 (AES-128)")
    print("=" * 70)
    print(f"Aluno A (Lorena):   {mat_a}")
    print(f"Aluno B (Mateus):   {mat_b}\n")

    # 1. Chave
    key_ascii, key_bytes = derive_key(mat_a, mat_b)
    print("[-] 1. DADOS DA CHAVE:")
    print(f"    Chave (ASCII):     {key_ascii}")
    print(f"    Chave (Hex):       {key_bytes.hex()}")

    # 2. Mensagem e PKCS#7
    raw_msg = f"A:{mat_a};B:{mat_b}".encode('ascii')
    padded_msg = apply_pkcs7(raw_msg)
    num_blocks = len(padded_msg) // 16
    print(f"\n[-] 2. MENSAGEM:")
    print(f"    Texto Original ({len(raw_msg)} bytes): {raw_msg.decode('ascii')}")
    print(f"    Com PKCS#7 ({len(padded_msg)} bytes / {num_blocks} blocos): {padded_msg.hex()}")
    for i in range(num_blocks):
        blk = padded_msg[16*i : 16*(i+1)]
        print(f"      Bloco {i+1} (Hex): {blk.hex()}")

    # 3. Cifragem ECB
    cipher_blocks = []
    for i in range(num_blocks):
        blk = padded_msg[16*i : 16*(i+1)]
        c_blk = aes_encrypt_block(blk, key_bytes)
        cipher_blocks.append(c_blk)
    full_cipher = b''.join(cipher_blocks)
    print(f"\n[-] 3. TEXTO CIFRADO FINAL (ECB):")
    print(f"    Total ({len(full_cipher)} bytes): {full_cipher.hex()}")
    for i, c in enumerate(cipher_blocks):
        print(f"      Cifrado Bloco {i+1}: {c.hex()}")

    # 4. Chaves de Rodada 0 e 1
    w = key_expansion(key_bytes)
    # Cada chave de rodada é formada por 4 palavras de 32 bits (16 bytes)
    def words_to_hex(words):
        res = bytearray()
        for word in words:
            res.extend(word)
        return res.hex()

    round_key_0 = words_to_hex(w[0:4])
    round_key_1 = words_to_hex(w[4:8])
    print(f"\n[-] 4. CHAVES DE RODADA DA EXPANSÃO:")
    print(f"    Chave de Rodada 0 (Hex): {round_key_0}")
    print(f"    Chave de Rodada 1 (Hex): {round_key_1}")

    # 5. Cinco estados intermediários do Bloco 1 (Rodada 1)
    b1 = padded_msg[0:16]
    state = bytes_to_state(b1)
    print(f"\n[-] 5. CINCO ESTADOS DO BLOCO 1 (RODADA 1):")
    print(f"    Estado 0 (Entrada Bloco 1):              {state_to_bytes(state).hex()}")
    
    # Fase 1: AddRoundKey inicial (Chave 0 - Whitening)
    add_round_key(state, w[0:4])
    s1 = state_to_bytes(state).hex()
    print(f"    (1) Após AddRoundKey Inicial (Chave 0):  {s1}")

    # Fase 2: SubBytes
    sub_bytes(state)
    s2 = state_to_bytes(state).hex()
    print(f"    (2) Após SubBytes:                       {s2}")

    # Fase 3: ShiftRows
    shift_rows(state)
    s3 = state_to_bytes(state).hex()
    print(f"    (3) Após ShiftRows:                      {s3}")

    # Fase 4: MixColumns
    mix_columns(state)
    s4 = state_to_bytes(state).hex()
    print(f"    (4) Após MixColumns:                     {s4}")

    # Fase 5: AddRoundKey (Chave 1)
    add_round_key(state, w[4:8])
    s5 = state_to_bytes(state).hex()
    print(f"    (5) Após AddRoundKey (Chave 1):          {s5}")

    # 6. Efeito Avalanche
    print(f"\n[-] 6. ANÁLISE DO EFEITO AVALANCHE (BLOCO 1):")
    c1_original = cipher_blocks[0]
    
    # Caso A: Inverter 1 bit no texto claro (bit menos significativo do byte 0)
    b1_flipped = bytearray(b1)
    b1_flipped[0] ^= 0x01
    c1_plain_flipped = aes_encrypt_block(bytes(b1_flipped), key_bytes)
    diff_plain = count_bits_different(c1_original, c1_plain_flipped)
    pct_plain = (diff_plain / 128.0) * 100.0
    print(f"    - Inversão de 1 bit na Mensagem:")
    print(f"      Original C1:  {c1_original.hex()}")
    print(f"      Modificado:   {c1_plain_flipped.hex()}")
    print(f"      Bits divergentes: {diff_plain}/128 ({pct_plain:.2f}%) [Esperado ~50%]")

    # Caso B: Inverter 1 bit na chave (bit menos significativo do byte 0)
    key_flipped = bytearray(key_bytes)
    key_flipped[0] ^= 0x01
    c1_key_flipped = aes_encrypt_block(b1, bytes(key_flipped))
    diff_key = count_bits_different(c1_original, c1_key_flipped)
    pct_key = (diff_key / 128.0) * 100.0
    print(f"\n    - Inversão de 1 bit na Chave:")
    print(f"      Original C1:  {c1_original.hex()}")
    print(f"      Modificado:   {c1_key_flipped.hex()}")
    print(f"      Bits divergentes: {diff_key}/128 ({pct_key:.2f}%) [Esperado ~50%]")
    print("=" * 70)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gerador de Análise Criptográfica da Etapa 3")
    parser.add_argument("--mat-a", default="2023278440028", help="Matrícula da Aluna A (Lorena)")
    parser.add_argument("--mat-b", default="2023278440030", help="Matrícula do Aluno B (Mateus)")
    args = parser.parse_args()
    analyze(args.mat_a, args.mat_b)

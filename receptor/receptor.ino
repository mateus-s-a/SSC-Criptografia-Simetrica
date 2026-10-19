/*
 * ============================================================================
 * PROJETO: AES-128 em Dois ESP32 via UART
 * DISCIPLINA: Segurança de Sistemas de Computação - IFMT
 * ALUNOS: Lorena Strobel e Mateus de Souza
 * PROFESSOR: Dr. Ruy de Oliveira
 * 
 * MÓDULO: Receptor (RX) - Placa B (Versão Oficial para Placa Física / GitHub)
 * RESPONSÁVEL: Lorena (Aluno A)
 * 
 * MATRÍCULAS DA DUPLA:
 *   - Aluno A (Lorena): 2023278440028 -> 8 últimos dígitos: 78440028
 *   - Aluno B (Mateus): 2023278440030 -> 8 últimos dígitos: 78440030
 * 
 * CHAVE SIMÉTRICA (16 bytes ASCII): "7844002878440030"
 * 
 * FORMATOS DE MENSAGEM SUPORTADOS DINAMICAMENTE PELO RECEPTOR (PKCS#7):
 * - Opção A (Matrícula Completa 13 dígitos): "A:2023278440028;B:2023278440030"
 *   Tamanho: 31 bytes + 1 byte de preenchimento (0x01) = 32 bytes (2 blocos AES)
 * - Opção B (Matrícula Reduzida 8 dígitos):  "A:78440028;B:78440030"
 *   Tamanho: 21 bytes + 11 bytes de preenchimento (0x0B) = 32 bytes (2 blocos AES)
 * O receptor valida e decifra qualquer uma das opções perfeitamente em tempo de execução.
 * 
 * ESPECIFICAÇÃO DE HARDWARE E COMUNICAÇÃO:
 * - Microcontrolador: ESP32 
 * - UART2 nos pinos: RX = GPIO 16 (recebe do TX) e TX = GPIO 17
 * - Velocidade: 115200 bps, 8N1
 * - Formato do quadro binário bruto: [0xAA, n_blocos, carga_cifrada (n * 16 bytes)]
 * - Proteção por tempo limite (timeout) de 2000 ms contra travamentos
 * ============================================================================
 */

#include <Arduino.h>

// -----------------------------------------------------------------------------
// 1. PINAGEM E CONFIGURAÇÃO DA UART2
// -----------------------------------------------------------------------------
#define PINO_RXD2 16
#define PINO_TXD2 17
#define VELOCIDADE_UART 115200
#define TEMPO_LIMITE_MS 2000 // Tempo limite de 2000 ms para recepção de dados

// Marcador fixo de início de quadro de transmissão
#define BYTE_SINCRONISMO 0xAA

// Chave da dupla: 8 dígitos Lorena (78440028) + 8 dígitos Mateus (78440030)
const uint8_t CHAVE_AES[16] = {
    '7', '8', '4', '4', '0', '0', '2', '8',
    '7', '8', '4', '4', '0', '0', '3', '0'
};

// -----------------------------------------------------------------------------
// 2. TABELAS CRIPTOGRÁFICAS (S-Box, S-Box Inversa, Constantes Rcon)
// -----------------------------------------------------------------------------

// S-Box direta: utilizada na Expansão de Chave (SubWord)
static const uint8_t tabela_sbox[256] = {
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
};

// S-Box Inversa: utilizada para decifrar (InvSubBytes)
static const uint8_t tabela_sbox_inversa[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Constantes de rodada Rcon (10 rodadas do AES-128)
static const uint8_t constante_rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Matriz para guardar as 11 subchaves geradas na expansão (Rodadas 0 a 10)
static uint8_t chaves_de_rodada[11][4][4];

// -----------------------------------------------------------------------------
// 3. PRIMITIVAS MATEMÁTICAS NO CORPO GF(2^8)
// -----------------------------------------------------------------------------

// Multiplicação por 0x02 (xtime) no corpo de Galois com polinômio redutor 0x11B
static inline uint8_t multiplicar_por_02(uint8_t b) {
    return (uint8_t)((b & 0x80) ? ((b << 1) ^ 0x1B) : (b << 1));
}

// Multiplicações da matriz InvMixColumns derivadas puramente com xtime e XOR:
// {09} = 2^3 + 1
static inline uint8_t multiplicar_por_09(uint8_t b) {
    return (uint8_t)(multiplicar_por_02(multiplicar_por_02(multiplicar_por_02(b))) ^ b);
}

// {0b} = 2^3 + 2 + 1
static inline uint8_t multiplicar_por_0b(uint8_t b) {
    return (uint8_t)(multiplicar_por_02(multiplicar_por_02(multiplicar_por_02(b))) ^ multiplicar_por_02(b) ^ b);
}

// {0d} = 2^3 + 2^2 + 1
static inline uint8_t multiplicar_por_0d(uint8_t b) {
    return (uint8_t)(multiplicar_por_02(multiplicar_por_02(multiplicar_por_02(b))) ^ multiplicar_por_02(multiplicar_por_02(b)) ^ b);
}

// {0e} = 2^3 + 2^2 + 2
static inline uint8_t multiplicar_por_0e(uint8_t b) {
    return (uint8_t)(multiplicar_por_02(multiplicar_por_02(multiplicar_por_02(b))) ^ multiplicar_por_02(multiplicar_por_02(b)) ^ multiplicar_por_02(b));
}

// -----------------------------------------------------------------------------
// 4. ETAPAS FUNDAMENTAIS DO AES-128
// -----------------------------------------------------------------------------

// Expansão de Chave (KeyExpansion): Gera as 11 chaves de rodada (44 palavras de 32 bits)
void expansao_de_chave(const uint8_t chave[16], uint8_t chaves_saida[11][4][4]) {
    uint8_t w[44][4];

    // As 4 primeiras palavras (w[0] a w[3]) recebem a própria chave mestra
    for (int i = 0; i < 4; i++) {
        w[i][0] = chave[4 * i + 0];
        w[i][1] = chave[4 * i + 1];
        w[i][2] = chave[4 * i + 2];
        w[i][3] = chave[4 * i + 3];
    }

    // Geração iterativa das palavras restantes w[4] até w[43]
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        temp[0] = w[i - 1][0];
        temp[1] = w[i - 1][1];
        temp[2] = w[i - 1][2];
        temp[3] = w[i - 1][3];

        if (i % 4 == 0) {
            // RotWord: Rotação circular de 1 byte para a esquerda
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // SubWord: Substituição byte a byte pela S-Box
            temp[0] = tabela_sbox[temp[0]];
            temp[1] = tabela_sbox[temp[1]];
            temp[2] = tabela_sbox[temp[2]];
            temp[3] = tabela_sbox[temp[3]];

            // Aplicação da constante de rodada Rcon no primeiro byte
            temp[0] ^= constante_rcon[i / 4];
        }

        w[i][0] = (uint8_t)(w[i - 4][0] ^ temp[0]);
        w[i][1] = (uint8_t)(w[i - 4][1] ^ temp[1]);
        w[i][2] = (uint8_t)(w[i - 4][2] ^ temp[2]);
        w[i][3] = (uint8_t)(w[i - 4][3] ^ temp[3]);
    }

    // Organização em matrizes 4x4 por rodada (ordem coluna por coluna)
    for (int rnd = 0; rnd < 11; rnd++) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                chaves_saida[rnd][r][c] = w[rnd * 4 + c][r];
            }
        }
    }
}

// Adição da Chave de Rodada (AddRoundKey): Operação XOR entre estado e a subchave
void AddRoundKey(uint8_t estado[4][4], const uint8_t chave_rodada[4][4]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            estado[r][c] ^= chave_rodada[r][c];
        }
    }
}

// Substituição Inversa de Bytes (InvSubBytes): Aplica a S-Box inversa em cada byte
void InvSubBytes(uint8_t estado[4][4]) {
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            estado[r][c] = tabela_sbox_inversa[estado[r][c]];
        }
    }
}

// Deslocamento Inverso de Linhas (InvShiftRows): Desloca ciclicamente as linhas para a DIREITA
void InvShiftRows(uint8_t estado[4][4]) {
    uint8_t temp;

    // Linha 1: Desloca 1 byte à direita
    temp = estado[1][3];
    estado[1][3] = estado[1][2];
    estado[1][2] = estado[1][1];
    estado[1][1] = estado[1][0];
    estado[1][0] = temp;

    // Linha 2: Desloca 2 bytes
    temp = estado[2][0]; estado[2][0] = estado[2][2]; estado[2][2] = temp;
    temp = estado[2][1]; estado[2][1] = estado[2][3]; estado[2][3] = temp;

    // Linha 3: Desloca 3 bytes à direita
    temp = estado[3][0];
    estado[3][0] = estado[3][1];
    estado[3][1] = estado[3][2];
    estado[3][2] = estado[3][3];
    estado[3][3] = temp;
}

// Mistura Inversa de Colunas (InvMixColumns): Multiplicação matricial no corpo GF(2^8)
void InvMixColumns(uint8_t estado[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t s0 = estado[0][c];
        uint8_t s1 = estado[1][c];
        uint8_t s2 = estado[2][c];
        uint8_t s3 = estado[3][c];

        estado[0][c] = multiplicar_por_0e(s0) ^ multiplicar_por_0b(s1) ^ multiplicar_por_0d(s2) ^ multiplicar_por_09(s3);
        estado[1][c] = multiplicar_por_09(s0) ^ multiplicar_por_0e(s1) ^ multiplicar_por_0b(s2) ^ multiplicar_por_0d(s3);
        estado[2][c] = multiplicar_por_0d(s0) ^ multiplicar_por_09(s1) ^ multiplicar_por_0e(s2) ^ multiplicar_por_0b(s3);
        estado[3][c] = multiplicar_por_0b(s0) ^ multiplicar_por_0d(s1) ^ multiplicar_por_09(s2) ^ multiplicar_por_0e(s3);
    }
}

// Decifrador de 1 bloco de 16 bytes (AES-128 Decrypt)
void decifrar_bloco_aes128(const uint8_t bloco_cifrado[16], uint8_t bloco_claro[16]) {
    uint8_t estado[4][4];

    // Carrega o vetor de entrada na matriz de estado 4x4 (coluna por coluna)
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            estado[r][c] = bloco_cifrado[r + 4 * c];
        }
    }

    // Rodada inicial inversa: Adiciona a Subchave 10 (AddRoundKey)
    AddRoundKey(estado, chaves_de_rodada[10]);

    // Rodadas intermediárias 9 até 1:
    // Deslocamento Inverso -> Substituição Inversa -> Adiciona Chave -> Mistura Inversa
    for (int rnd = 9; rnd >= 1; rnd--) {
        InvShiftRows(estado);
        InvSubBytes(estado);
        AddRoundKey(estado, chaves_de_rodada[rnd]);
        InvMixColumns(estado);
    }

    // Rodada final (Round 0): Não executa a Mistura de Colunas!
    InvShiftRows(estado);
    InvSubBytes(estado);
    AddRoundKey(estado, chaves_de_rodada[0]);

    // Descarrega o estado decifrado no vetor de saída (coluna por coluna)
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            bloco_claro[r + 4 * c] = estado[r][c];
        }
    }
}

// -----------------------------------------------------------------------------
// 5. REMOÇÃO E VALIDAÇÃO DO PREENCHIMENTO PKCS#7
// -----------------------------------------------------------------------------
int remover_padding_pkcs7(uint8_t *buffer, int tamanho) {
    if (tamanho <= 0 || (tamanho % 16) != 0) {
        return -1;
    }

    uint8_t tamanho_padding = buffer[tamanho - 1];

    if (tamanho_padding == 0 || tamanho_padding > 16 || tamanho_padding > (uint8_t)tamanho) {
        return -1;
    }

    // Confere se todos os últimos 'tamanho_padding' bytes têm o mesmo valor
    for (int i = 0; i < tamanho_padding; i++) {
        if (buffer[tamanho - 1 - i] != tamanho_padding) {
            return -1;
        }
    }

    int tamanho_sem_padding = tamanho - tamanho_padding;
    buffer[tamanho_sem_padding] = '\0'; // Insere terminador de string nulo
    return tamanho_sem_padding;
}

// -----------------------------------------------------------------------------
// 6. AUTO-TESTE INICIAL (NIST FIPS-197)
// -----------------------------------------------------------------------------
void executar_auto_teste_inicial() {
    Serial.println("\n==================================================");
    Serial.println("  AUTO-TESTE DE INTEGRIDADE (NIST FIPS-197)");
    Serial.println("==================================================");

    // Teste 1: Vetor Oficial NIST FIPS-197 Apêndice B
    const uint8_t chave_fips_b[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t cifrado_fips_b[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    const uint8_t claro_esperado_fips_b[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    uint8_t subchaves_temporarias[11][4][4];
    expansao_de_chave(chave_fips_b, subchaves_temporarias);

    uint8_t chaves_originais[11][4][4];
    memcpy(chaves_originais, chaves_de_rodada, sizeof(chaves_de_rodada));
    memcpy(chaves_de_rodada, subchaves_temporarias, sizeof(chaves_de_rodada));

    uint8_t saida_teste[16];
    decifrar_bloco_aes128(cifrado_fips_b, saida_teste);

    if (memcmp(saida_teste, claro_esperado_fips_b, 16) == 0) {
        Serial.println("[VETOR FIPS-197 APÊNDICE B]: SUCESSO");
    } else {
        Serial.println("[VETOR FIPS-197 APÊNDICE B]: FALHA!");
    }

    // Teste 2: Vetor Oficial NIST FIPS-197 Apêndice C.1
    const uint8_t chave_fips_c[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t cifrado_fips_c[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    const uint8_t claro_esperado_fips_c[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };

    expansao_de_chave(chave_fips_c, subchaves_temporarias);
    memcpy(chaves_de_rodada, subchaves_temporarias, sizeof(chaves_de_rodada));
    decifrar_bloco_aes128(cifrado_fips_c, saida_teste);

    if (memcmp(saida_teste, claro_esperado_fips_c, 16) == 0) {
        Serial.println("[VETOR FIPS-197 APÊNDICE C.1]: SUCESSO");
    } else {
        Serial.println("[VETOR FIPS-197 APÊNDICE C.1]: FALHA!");
    }

    // Restaura as subchaves da dupla
    memcpy(chaves_de_rodada, chaves_originais, sizeof(chaves_de_rodada));
    Serial.println("==================================================\n");
}

// -----------------------------------------------------------------------------
// 7. SETUP DO ESP32 (INICIALIZAÇÃO DO RECEPTOR)
// -----------------------------------------------------------------------------
void setup() {
    // Inicialização do Monitor Serial USB
    Serial.begin(115200);
    delay(1000);

    Serial.println("\n[SISTEMA INICIADO] Receptor B - AES-128 ECB");
    Serial.printf("[HARDWARE] UART2 no pino RX=%d a %d bps\n", PINO_RXD2, VELOCIDADE_UART);

    // Inicialização da UART2 nos pinos RX=16 e TX=17
    Serial2.begin(VELOCIDADE_UART, SERIAL_8N1, PINO_RXD2, PINO_TXD2);

    // Pré-calcula a expansão de chave do AES-128 na memória
    expansao_de_chave(CHAVE_AES, chaves_de_rodada);
    Serial.print("[CHAVE SIMÉTRICA (ASCII)]: ");
    for (int i = 0; i < 16; i++) Serial.print((char)CHAVE_AES[i]);
    Serial.println();

    // Executa a bateria de auto-testes iniciais (FIPS-197 Apêndices B, C.1 e vetor da dupla)
    executar_auto_teste_inicial();

    Serial.println("[AGUARDANDO PACOTES NA UART2] Pronto para receber transmissões...\n");
}

// -----------------------------------------------------------------------------
// 8. LOOP PRINCIPAL (ESCUTA PASSIVA E PROCESSAMENTO DE QUADROS DA UART2)
// -----------------------------------------------------------------------------
void loop() {
    // -------------------------------------------------------------------------
    // MÁQUINA DE ESTADOS DE RECEPÇÃO COM TEMPO LIMITE (TIMEOUT)
    // -------------------------------------------------------------------------
    // Passo 1: Sincronização - aguarda a chegada do marcador fixo 0xAA
    if (Serial2.available()) {
        uint8_t byte_recebido = Serial2.read();
        if (byte_recebido != BYTE_SINCRONISMO) {
            // Descarta bytes de ruído até alinhar no marcador de início 0xAA
            return;
        }

        Serial.println("\n--------------------------------------------------");
        Serial.println("[UART2] Marcador de sincronismo 0xAA detectado!");

        // Passo 2: Leitura do número de blocos (n) com proteção por timeout
        uint32_t tempo_inicio = millis();
        while (!Serial2.available()) {
            if (millis() - tempo_inicio > TEMPO_LIMITE_MS) {
                Serial.println("[ERRO] Timeout aguardando byte de contagem de blocos (n). Descartando.");
                return;
            }
        }

        uint8_t quantidade_blocos = Serial2.read();
        Serial.printf("[UART2] Número de blocos declarados: %d\n", quantidade_blocos);

        if (quantidade_blocos == 0 || quantidade_blocos > 16) {
            Serial.printf("[ERRO] Quantidade de blocos inválida (%d). Rejeitando pacote.\n", quantidade_blocos);
            return;
        }

        uint16_t total_bytes_carga = quantidade_blocos * 16;
        uint8_t buffer_cifrado[256];
        uint16_t bytes_recebidos = 0;

        // Passo 3: Leitura segura de todos os bytes cifrados brutos
        Serial.printf("[UART2] Aguardando %d bytes brutos da carga cifrada...\n", total_bytes_carga);
        tempo_inicio = millis();
        while (bytes_recebidos < total_bytes_carga) {
            if (Serial2.available()) {
                buffer_cifrado[bytes_recebidos++] = Serial2.read();
                tempo_inicio = millis(); // Reinicia janela de timeout ao receber novos dados
            }
            if (millis() - tempo_inicio > TEMPO_LIMITE_MS) {
                Serial.printf("[ERRO] Timeout durante recepção da carga! Recebidos %d de %d bytes. Pacote descartado.\n",
                              bytes_recebidos, total_bytes_carga);
                return;
            }
        }

        Serial.println("[UART2] Pacote completo recebido com sucesso!");

        Serial.print("[HEX RECEBIDO]: ");
        for (int i = 0; i < total_bytes_carga; i++) {
            if (buffer_cifrado[i] < 0x10) Serial.print("0");
            Serial.print(buffer_cifrado[i], HEX);
            Serial.print(" ");
        }
        Serial.println();

        // Passo 4: Decifragem Bloco a Bloco em modo ECB
        uint8_t buffer_decifrado[257]; // +1 para terminador nulo '\0'
        for (uint8_t blk = 0; blk < quantidade_blocos; blk++) {
            decifrar_bloco_aes128(&buffer_cifrado[blk * 16], &buffer_decifrado[blk * 16]);
        }

        Serial.print("[HEX DECIFRADO COM PADDING]: ");
        for (int i = 0; i < total_bytes_carga; i++) {
            if (buffer_decifrado[i] < 0x10) Serial.print("0");
            Serial.print(buffer_decifrado[i], HEX);
            Serial.print(" ");
        }
        Serial.println();

        // Passo 5: Validação e Remoção do Preenchimento PKCS#7
        int tamanho_texto_claro = remover_padding_pkcs7(buffer_decifrado, total_bytes_carga);

        if (tamanho_texto_claro < 0) {
            Serial.println("[ERRO] Falha na validação do padding PKCS#7 (Preenchimento inválido ou corrompido)!");
        } else {
            uint8_t valor_padding = total_bytes_carga - tamanho_texto_claro;
            Serial.printf("[PKCS#7] Removidos %d bytes de padding com valor 0x%02X.\n", valor_padding, valor_padding);
            Serial.println("==================================================");
            Serial.println("  >>> MENSAGEM DECIFRADA COM SUCESSO <<<");
            Serial.printf("  Conteúdo (%d bytes): %s\n", tamanho_texto_claro, (char*)buffer_decifrado);
            Serial.println("==================================================");
        }
    }
}

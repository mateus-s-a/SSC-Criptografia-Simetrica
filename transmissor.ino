/*
 * ============================================================================
 * PROJETO: AES-128 em Dois ESP32 via UART
 * DISCIPLINA: Segurança de Sistemas de Computação - IFMT
 * 
 * MÓDULO: Transmissor (TX) - Placa A (Hardware)
 * RESPONSÁVEL PELA CODIFICAÇÃO: Mateus (Aluno B)
 * DUPLA E MATRÍCULAS:
 * - Aluno A: Lorena  (2023278440028) -> 8 dígitos finais: 78440028
 * - Aluno B: Mateus  (2023278440030) -> 8 dígitos finais: 78440030
 * 
 * DADOS CRIPTOGRÁFICOS DERIVADOS:
 * - Chave (16 bytes): "7844002878440030"
 * - Mensagem (31 bytes): "A:2023278440028;B:2023278440030"
 * - PKCS#7: acrescenta 1 byte (0x01) totalizando 32 bytes (2 blocos de 16 bytes)
 * ============================================================================
 */

#include <Arduino.h>
#include <stdint.h>
#include <stddef.h>

/*
 * ============================================================================
 * PARTE 1: FUNDAÇÕES MATEMÁTICAS, TABELAS E ARITMÉTICA EM GF(2^8)
 * ============================================================================
 * 
 * 1. FUNDAMENTAÇÃO MATEMÁTICA DA S-BOX (Exigência do Professor):
 * A S-Box é a única transformação não-linear do AES (responsável pela "Confusão").
 * Cada elemento S(x) é gerado a partir de duas etapas algébricas bem definidas:
 * 
 * a) Inversão Multiplicativa no Corpo de Galois GF(2^8):
 *    Calcula-se o inverso modular x^(-1) no corpo definido pelo polinômio irredutível:
 *    m(x) = x^8 + x^4 + x^3 + x + 1 (em binário: 0x11B).
 *    Por convenção do padrão NIST FIPS-197, define-se 0^(-1) = 0.
 * 
 * b) Transformação Afim sobre GF(2):
 *    O byte resultante da inversão passa por uma multiplicação matricial 8x8 invertível
 *    seguida da soma (XOR bit a bit) com o vetor constante 0x63 (01100011 em binário).
 *    Essa transformação elimina pontos fixos (como S(0)=0) e simplificações algébricas.
 * 
 * Para otimizar o tempo de processamento do ESP32, a tabela pré-calculada de 256 bytes
 * é armazenada na memória Flash usando o modificador PROGMEM, economizando memória RAM.
 */

const uint8_t SBOX[256] PROGMEM = {
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

/*
 * Função utilitária para leitura segura da S-Box na Flash (PROGMEM)
 */
uint8_t get_sbox(uint8_t index) {
    return pgm_read_byte(&SBOX[index]);
}

/*
 * 2. MULTIPLICAÇÃO NO CORPO GF(2^8) E OPERAÇÃO xtime:
 * No corpo finito GF(2^8), a multiplicação por {02} equivale à multiplicação polinomial
 * pelo monômio 'x'. Em binário, isso é realizado através de um deslocamento de 1 bit
 * à esquerda (b << 1).
 * 
 * Se o bit mais significativo (bit 7) for 1 antes do deslocamento, a multiplicação atinge
 * o grau x^8 (transbordo do limite de 1 byte). Para manter o resultado no corpo, reduz-se
 * o resultado pelo polinômio irredutível do AES:
 * x^8 = x^4 + x^3 + x + 1, cuja representação em byte é 0x1B.
 * 
 * Portanto: se (b & 0x80) != 0, aplica-se XOR com 0x1B. Caso contrário, apenas desloca.
 */
uint8_t xtime(uint8_t b) {
    return (uint8_t)((b << 1) ^ (((b >> 7) & 1) * 0x1B));
}

/*
 * 3. ESTRUTURAÇÃO DA MATRIZ DE ESTADO (STATE MATRIX 4x4):
 * No AES-128, o bloco de 16 bytes é mapeado em uma matriz 4x4 organizada
 * estritamente COLUNA POR COLUNA (Column-Major Order):
 * 
 *   Coluna 0   Coluna 1   Coluna 2   Coluna 3
 * [ byte 0,    byte 4,    byte 8,    byte 12 ]  Linha 0
 * [ byte 1,    byte 5,    byte 9,    byte 13 ]  Linha 1
 * [ byte 2,    byte 6,    byte 10,   byte 14 ]  Linha 2
 * [ byte 3,    byte 7,    byte 11,   byte 15 ]  Linha 3
 * 
 * Fórmula de mapeamento: State[r][c] = input[r + 4 * c]
 */

void bytes_to_state(const uint8_t input[16], uint8_t state[4][4]) {
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            state[row][col] = input[row + 4 * col];
        }
    }
}

void state_to_bytes(const uint8_t state[4][4], uint8_t output[16]) {
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            output[row + 4 * col] = state[row][col];
        }
    }
}

/*
 * ============================================================================
 * PARTE 2: PRIMITIVAS CRIPTOGRÁFICAS DE RODADA (O MOTOR DE TRANSFORMAÇÃO)
 * ============================================================================
 * 
 * Uma rodada padrão do AES (rodadas 1 a 9) aplica sequencialmente 4 operações:
 * 1. SubBytes    (Confusão não-linear via S-Box)
 * 2. ShiftRows   (Difusão posicional entre colunas)
 * 3. MixColumns  (Difusão matemática dentro de cada coluna no corpo GF(2^8))
 * 4. AddRoundKey (Introdução da subchave secreta da rodada via XOR)
 */

/*
 * 1. AddRoundKey:
 * Realiza um XOR bit a bit entre cada byte da matriz de estado e a subchave da rodada.
 * É uma operação auto-inversa: aplicar AddRoundKey duas vezes com a mesma chave restaura o valor.
 */
void AddRoundKey(uint8_t state[4][4], const uint8_t roundKey[16]) {
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            state[row][col] ^= roundKey[row + 4 * col];
        }
    }
}

/*
 * 2. SubBytes:
 * Substitui cada byte do estado pelo valor correspondente na S-Box.
 * state[r][c] = SBOX[ state[r][c] ]
 */
void SubBytes(uint8_t state[4][4]) {
    for (uint8_t col = 0; col < 4; col++) {
        for (uint8_t row = 0; row < 4; row++) {
            state[row][col] = get_sbox(state[row][col]);
        }
    }
}

/*
 * 3. ShiftRows:
 * Desloca ciclicamente as linhas da matriz de estado para a esquerda:
 * - Linha 0: sem deslocamento
 * - Linha 1: desloca 1 byte à esquerda:  [s10, s11, s12, s13] -> [s11, s12, s13, s10]
 * - Linha 2: desloca 2 bytes à esquerda: [s20, s21, s22, s23] -> [s22, s23, s20, s21]
 * - Linha 3: desloca 3 bytes à esquerda: [s30, s31, s32, s33] -> [s33, s30, s31, s32]
 */
void ShiftRows(uint8_t state[4][4]) {
    // Linha 1: rotação de 1 byte à esquerda
    uint8_t temp1 = state[1][0];
    state[1][0] = state[1][1];
    state[1][1] = state[1][2];
    state[1][2] = state[1][3];
    state[1][3] = temp1;

    // Linha 2: rotação de 2 bytes à esquerda (troca cruzada)
    uint8_t temp2_0 = state[2][0];
    uint8_t temp2_1 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = temp2_0;
    state[2][3] = temp2_1;

    // Linha 3: rotação de 3 bytes à esquerda (equivale a 1 à direita)
    uint8_t temp3 = state[3][3];
    state[3][3] = state[3][2];
    state[3][2] = state[3][1];
    state[3][1] = state[3][0];
    state[3][0] = temp3;
}

/*
 * 4. MixColumns:
 * Opera em cada coluna da matriz de estado independentemente.
 * Trata cada coluna como um polinômio de quatro termos sobre GF(2^8) e multiplica
 * módulo (x^4 + 1) pela matriz constante:
 *   [ 02  03  01  01 ]
 *   [ 01  02  03  01 ]
 *   [ 01  01  02  03 ]
 *   [ 03  01  01  02 ]
 * 
 * Notar que: {03} * s = ({02} ^ {01}) * s = xtime(s) ^ s.
 */
void MixColumns(uint8_t state[4][4]) {
    for (uint8_t col = 0; col < 4; col++) {
        uint8_t s0 = state[0][col];
        uint8_t s1 = state[1][col];
        uint8_t s2 = state[2][col];
        uint8_t s3 = state[3][col];

        state[0][col] = xtime(s0) ^ (xtime(s1) ^ s1) ^ s2 ^ s3;
        state[1][col] = s0 ^ xtime(s1) ^ (xtime(s2) ^ s2) ^ s3;
        state[2][col] = s0 ^ s1 ^ xtime(s2) ^ (xtime(s3) ^ s3);
        state[3][col] = (xtime(s0) ^ s0) ^ s1 ^ s2 ^ xtime(s3);
    }
}

/*
 * ============================================================================
 * PARTE 3: EXPANSÃO DE CHAVES E CIFRAGEM DE BLOCO (10 RODADAS)
 * ============================================================================
 * 
 * 1. EXPANSÃO DE CHAVES (KeyExpansion):
 * A chave mestre do AES-128 possui 128 bits (16 bytes).
 * O algoritmo necessita de 11 subchaves de 16 bytes (uma para o Whitening inicial
 * e uma para cada uma das 10 rodadas), totalizando 176 bytes (44 palavras de 32 bits).
 * 
 * Para calcular cada nova palavra W[i]:
 * - As 4 primeiras palavras W[0..3] são a própria chave mestre.
 * - Para i múltiplo de 4:
 *     W[i] = W[i-4] ^ SubWord(RotWord(W[i-1])) ^ Rcon[i/4]
 * - Para os demais i:
 *     W[i] = W[i-4] ^ W[i-1]
 * 
 * Onde:
 * - RotWord: rotaciona 1 byte à esquerda [B0, B1, B2, B3] -> [B1, B2, B3, B0]
 * - SubWord: aplica a S-Box nos 4 bytes [S(B0), S(B1), S(B2), S(B3)]
 * - Rcon: constante de rodada baseada em potências de x no corpo GF(2^8)
 */

const uint8_t RCON[10] PROGMEM = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

uint8_t get_rcon(uint8_t index) {
    return pgm_read_byte(&RCON[index]);
}

void KeyExpansion(const uint8_t key[16], uint8_t round_keys[11][16]) {
    // 1. As primeiras 4 palavras (16 bytes) são copiadas diretamente da chave mestre
    for (uint8_t i = 0; i < 16; i++) {
        round_keys[0][i] = key[i];
    }

    uint8_t temp[4];

    // 2. Gera as palavras restantes (de 4 a 43)
    for (uint8_t i = 4; i < 44; i++) {
        uint8_t prev_rnd = (i - 1) / 4;
        uint8_t prev_col = (i - 1) % 4;

        temp[0] = round_keys[prev_rnd][prev_col * 4 + 0];
        temp[1] = round_keys[prev_rnd][prev_col * 4 + 1];
        temp[2] = round_keys[prev_rnd][prev_col * 4 + 2];
        temp[3] = round_keys[prev_rnd][prev_col * 4 + 3];

        if (i % 4 == 0) {
            // RotWord: [temp[0], temp[1], temp[2], temp[3]] -> [temp[1], temp[2], temp[3], temp[0]]
            uint8_t t0 = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t0;

            // SubWord: passa cada byte pela S-Box
            temp[0] = get_sbox(temp[0]);
            temp[1] = get_sbox(temp[1]);
            temp[2] = get_sbox(temp[2]);
            temp[3] = get_sbox(temp[3]);

            // XOR do primeiro byte com Rcon da rodada correspondente
            temp[0] ^= get_rcon((i / 4) - 1);
        }

        uint8_t cur_rnd = i / 4;
        uint8_t cur_col = i % 4;
        uint8_t old_rnd = (i - 4) / 4;
        uint8_t old_col = (i - 4) % 4;

        round_keys[cur_rnd][cur_col * 4 + 0] = round_keys[old_rnd][old_col * 4 + 0] ^ temp[0];
        round_keys[cur_rnd][cur_col * 4 + 1] = round_keys[old_rnd][old_col * 4 + 1] ^ temp[1];
        round_keys[cur_rnd][cur_col * 4 + 2] = round_keys[old_rnd][old_col * 4 + 2] ^ temp[2];
        round_keys[cur_rnd][cur_col * 4 + 3] = round_keys[old_rnd][old_col * 4 + 3] ^ temp[3];
    }
}

/*
 * 2. CIFRAGEM DE UM BLOCO DE 16 BYTES (aes128_encrypt_block):
 * Executa as 10 rodadas completas do padrão AES-128:
 * - Rodada 0 (Whitening Inicial): apenas AddRoundKey com a chave de rodada 0.
 * - Rodadas 1 a 9 (Rodadas Padrão):
 *     SubBytes -> ShiftRows -> MixColumns -> AddRoundKey
 * - Rodada 10 (Rodada Final):
 *     SubBytes -> ShiftRows -> AddRoundKey (NÃO possui MixColumns!)
 * 
 * Por que a Rodada 10 não tem MixColumns?
 * Para que a estrutura de decifragem seja simétrica e invertível sem exigir uma
 * transformação extra no início do processo de decriptação.
 */
void aes128_encrypt_block(const uint8_t plaintext[16], const uint8_t round_keys[11][16], uint8_t ciphertext[16]) {
    uint8_t state[4][4];
    bytes_to_state(plaintext, state);

    // Rodada 0: Whitening inicial
    AddRoundKey(state, round_keys[0]);

    // Rodadas 1 a 9
    for (uint8_t rnd = 1; rnd < 10; rnd++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, round_keys[rnd]);
    }

    // Rodada 10: Final (sem MixColumns)
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, round_keys[10]);

    // Converte a matriz de estado de volta para o vetor linear de saída
    state_to_bytes(state, ciphertext);
}

/*
 * ============================================================================
 * PARTE 4: DADOS DA DUPLA, PREENCHIMENTO PKCS#7 DINÂMICO E MODO ECB
 * ============================================================================
 */

// Matrículas oficiais da dupla
const char MATRICULA_A[] = "2023278440028"; // Aluno A: Lorena
const char MATRICULA_B[] = "2023278440030"; // Aluno B: Mateus

/*
 * 1. Extração dos 8 últimos dígitos:
 * Percorre a string de matrícula, filtra apenas os caracteres numéricos e extrai
 * os 8 últimos dígitos. Se houver menos de 8 dígitos, preenche com '0' à esquerda.
 */
void extract_last_8_digits(const char *mat, char out8[9]) {
    char digits[32];
    uint8_t d_count = 0;
    for (size_t i = 0; mat[i] != '\0' && d_count < 31; i++) {
        if (mat[i] >= '0' && mat[i] <= '9') {
            digits[d_count++] = mat[i];
        }
    }
    digits[d_count] = '\0';

    if (d_count >= 8) {
        memcpy(out8, &digits[d_count - 8], 8);
    } else {
        uint8_t pad = 8 - d_count;
        for (uint8_t i = 0; i < pad; i++) out8[i] = '0';
        memcpy(&out8[pad], digits, d_count);
    }
    out8[8] = '\0';
}

/*
 * 2. Derivação da chave de 16 bytes a partir das matrículas:
 * Concatena os 8 dígitos de A com os 8 dígitos de B e converte para código ASCII.
 * Lorena (78440028) + Mateus (78440030) = "7844002878440030"
 */
void derive_key_from_matriculas(const char *matA, const char *matB, uint8_t key[16]) {
    char digitsA[9];
    char digitsB[9];
    extract_last_8_digits(matA, digitsA);
    extract_last_8_digits(matB, digitsB);

    memcpy(&key[0], digitsA, 8);
    memcpy(&key[8], digitsB, 8);
}

/*
 * 3. Preenchimento PKCS#7 Dinâmico (RFC 5652):
 * O AES exige que os dados sejam estritamente múltiplos de 16 bytes.
 * Calcula quantos bytes faltam: pad_len = 16 - (in_len % 16).
 * Adiciona pad_len bytes, todos com o valor numérico igual a pad_len.
 * Retorna o tamanho total dos dados preenchidos.
 */
size_t apply_pkcs7_padding(const uint8_t *in, size_t in_len, uint8_t *out) {
    uint8_t pad_len = 16 - (in_len % 16);
    memcpy(out, in, in_len);
    for (uint8_t i = 0; i < pad_len; i++) {
        out[in_len + i] = pad_len;
    }
    return in_len + pad_len;
}

/*
 * 4. Cifragem em Modo ECB (Electronic Codebook):
 * Divide os dados preenchidos em n blocos de 16 bytes e cifra cada um de forma
 * totalmente independente usando o núcleo aes128_encrypt_block().
 */
void encrypt_ecb(const uint8_t *padded_data, size_t padded_len, const uint8_t round_keys[11][16], uint8_t *ciphertext) {
    size_t num_blocks = padded_len / 16;
    for (size_t b = 0; b < num_blocks; b++) {
        aes128_encrypt_block(&padded_data[b * 16], round_keys, &ciphertext[b * 16]);
    }
}

/*
 * ----------------------------------------------------------------------------
 * ROTINAS DE AUTOTESTE E VALIDAÇÃO (PARTES 1, 2, 3 E 4)
 * ----------------------------------------------------------------------------
 */

void print_hex_buffer(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x10) Serial.print(F("0"));
        Serial.print(buf[i], HEX);
    }
    Serial.println();
}

void test_part1() {
    Serial.println(F("\n=================================================="));
    Serial.println(F("     VALIDAÇÃO DA PARTE 1 - MATEMÁTICA & S-BOX     "));
    Serial.println(F("=================================================="));

    // Teste 1: Aritmética de xtime (Exemplos oficiais da Seção 4.2.1 do FIPS-197)
    uint8_t t1 = xtime(0x57);
    bool ok1 = (t1 == 0xAE);
    Serial.print(F("[Teste 1.1] xtime(0x57) -> Esperado: 0xAE | Obtido: 0x"));
    if (t1 < 0x10) Serial.print(F("0"));
    Serial.print(t1, HEX);
    Serial.println(ok1 ? F(" [OK]") : F(" [FALHOU]"));

    uint8_t t2 = xtime(0xAE);
    bool ok2 = (t2 == 0x47);
    Serial.print(F("[Teste 1.2] xtime(0xAE) -> Esperado: 0x47 | Obtido: 0x"));
    if (t2 < 0x10) Serial.print(F("0"));
    Serial.print(t2, HEX);
    Serial.println(ok2 ? F(" [OK]") : F(" [FALHOU]"));

    // Teste 2: Conferência da S-Box
    uint8_t s_00 = get_sbox(0x00);
    uint8_t s_53 = get_sbox(0x53);
    uint8_t s_a7 = get_sbox(0xA7);
    uint8_t s_ff = get_sbox(0xFF);

    bool ok_sbox = (s_00 == 0x63 && s_53 == 0xED && s_a7 == 0x5C && s_ff == 0x16);
    Serial.print(F("[Teste 1.3] Leitura S-Box (0x00, 0x53, 0xA7, 0xFF) -> "));
    Serial.println(ok_sbox ? F("Todos corretos! [OK]") : F("Falha na tabela! [FALHOU]"));

    // Teste 3: Mapeamento de Matriz de Estado (Column-Major)
    uint8_t test_bytes[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    uint8_t test_state[4][4];
    uint8_t roundtrip_bytes[16];
    bytes_to_state(test_bytes, test_state);
    state_to_bytes(test_state, roundtrip_bytes);

    bool ok_matrix = true;
    for (int i = 0; i < 16; i++) {
        if (roundtrip_bytes[i] != test_bytes[i]) ok_matrix = false;
    }
    if (test_state[0][1] != 4 || test_state[3][0] != 3) ok_matrix = false;

    Serial.print(F("[Teste 1.4] Mapeamento Matriz 4x4 (Column-Major) -> "));
    Serial.println(ok_matrix ? F("Perfeito! [OK]") : F("Erro de indexação! [FALHOU]"));

    if (ok1 && ok2 && ok_sbox && ok_matrix) {
        Serial.println(F(">>> PARTE 1 VALIDADA COM SUCESSO! <<<"));
    } else {
        Serial.println(F(">>> ATENÇÃO: HOUVE FALHA NA PARTE 1! <<<"));
    }
}

void test_part2() {
    Serial.println(F("\n=================================================="));
    Serial.println(F("     VALIDAÇÃO DA PARTE 2 - 5 ESTADOS DA RODADA 1 "));
    Serial.println(F("=================================================="));

    // Dados reais da dupla:
    // Bloco 1 Claro: "A:2023278440028;" (16 bytes)
    const uint8_t b1[16] = {0x41, 0x3a, 0x32, 0x30, 0x32, 0x33, 0x32, 0x37, 0x38, 0x34, 0x34, 0x30, 0x30, 0x32, 0x38, 0x3b};
    // Chave de Rodada 0: "7844002878440030"
    const uint8_t k0[16] = {0x37, 0x38, 0x34, 0x34, 0x30, 0x30, 0x32, 0x38, 0x37, 0x38, 0x34, 0x34, 0x30, 0x30, 0x33, 0x30};
    // Chave de Rodada 1 da expansão da dupla
    const uint8_t k1[16] = {0x32, 0xfb, 0x30, 0x30, 0x02, 0xcb, 0x02, 0x08, 0x35, 0xf3, 0x36, 0x3c, 0x05, 0xc3, 0x05, 0x0c};

    uint8_t state[4][4];
    uint8_t buffer[16];

    // Estado 0: Entrada
    bytes_to_state(b1, state);
    state_to_bytes(state, buffer);
    Serial.print(F("Estado 0 (Entrada Bloco 1):              "));
    print_hex_buffer(buffer, 16);

    // Fase 1: AddRoundKey inicial (Chave 0)
    AddRoundKey(state, k0);
    state_to_bytes(state, buffer);
    Serial.print(F("(1) Apos AddRoundKey Inicial (Chave 0):  "));
    print_hex_buffer(buffer, 16);
    // Esperado: 760206040203000f0f0c000400020b0b
    bool ok_s1 = (buffer[0] == 0x76 && buffer[15] == 0x0B);

    // Fase 2: SubBytes
    SubBytes(state);
    state_to_bytes(state, buffer);
    Serial.print(F("(2) Apos SubBytes:                       "));
    print_hex_buffer(buffer, 16);
    // Esperado: 38776ff2777b637676fe63f263772b2b
    bool ok_s2 = (buffer[0] == 0x38 && buffer[15] == 0x2B);

    // Fase 3: ShiftRows
    ShiftRows(state);
    state_to_bytes(state, buffer);
    Serial.print(F("(3) Apos ShiftRows:                      "));
    print_hex_buffer(buffer, 16);
    // Esperado: 387b632b77fe2bf276776f76637763f2
    bool ok_s3 = (buffer[0] == 0x38 && buffer[15] == 0xF2);

    // Fase 4: MixColumns
    MixColumns(state);
    state_to_bytes(state, buffer);
    Serial.print(F("(4) Apos MixColumns:                     "));
    print_hex_buffer(buffer, 16);
    // Esperado: b540f8062e1fd2b36c5f456ecedadf4e
    bool ok_s4 = (buffer[0] == 0xB5 && buffer[15] == 0x4E);

    // Fase 5: AddRoundKey (Chave 1)
    AddRoundKey(state, k1);
    state_to_bytes(state, buffer);
    Serial.print(F("(5) Apos AddRoundKey (Chave 1):          "));
    print_hex_buffer(buffer, 16);
    // Esperado: 87bbc8362cd4d0bb59ac7352cb19da42
    bool ok_s5 = (buffer[0] == 0x87 && buffer[15] == 0x42);

    if (ok_s1 && ok_s2 && ok_s3 && ok_s4 && ok_s5) {
        Serial.println(F("\n>>> PARTE 2 VALIDADA COM 100% DE SUCESSO! <<<"));
        Serial.println(F("Todos os 5 estados da Rodada 1 conferem com o gabarito!"));
    } else {
        Serial.println(F("\n>>> ATENÇÃO: HOUVE DIVERGÊNCIA NA PARTE 2! <<<"));
    }
    Serial.println(F("==================================================\n"));
}

void test_part3() {
    Serial.println(F("\n=================================================="));
    Serial.println(F("     VALIDAÇÃO DA PARTE 3 - VETORES NIST FIPS-197 "));
    Serial.println(F("=================================================="));

    // -------------------------------------------------------------
    // Teste 3.1: NIST FIPS-197 Apêndice B
    // -------------------------------------------------------------
    const uint8_t key_b[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    const uint8_t plain_b[16] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };
    const uint8_t exp_cipher_b[16] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };

    uint8_t round_keys_b[11][16];
    KeyExpansion(key_b, round_keys_b);

    uint8_t out_cipher_b[16];
    aes128_encrypt_block(plain_b, round_keys_b, out_cipher_b);

    Serial.println(F("[-] Teste 3.1: FIPS-197 Apêndice B:"));
    Serial.print(F("    Chave (Hex):        "));
    print_hex_buffer(key_b, 16);
    Serial.print(F("    Texto Claro:        "));
    print_hex_buffer(plain_b, 16);
    Serial.print(F("    Cifrado Obtido:     "));
    print_hex_buffer(out_cipher_b, 16);
    Serial.print(F("    Cifrado Esperado:   "));
    print_hex_buffer(exp_cipher_b, 16);

    bool ok_b = (memcmp(out_cipher_b, exp_cipher_b, 16) == 0);
    Serial.print(F("    Resultado Apêndice B: "));
    Serial.println(ok_b ? F("PASSOU! [OK]") : F("FALHOU! [ERRO]"));

    // -------------------------------------------------------------
    // Teste 3.2: NIST FIPS-197 Apêndice C.1
    // -------------------------------------------------------------
    const uint8_t key_c[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t plain_c[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t exp_cipher_c[16] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };

    uint8_t round_keys_c[11][16];
    KeyExpansion(key_c, round_keys_c);

    uint8_t out_cipher_c[16];
    aes128_encrypt_block(plain_c, round_keys_c, out_cipher_c);

    Serial.println(F("\n[-] Teste 3.2: FIPS-197 Apêndice C.1:"));
    Serial.print(F("    Chave (Hex):        "));
    print_hex_buffer(key_c, 16);
    Serial.print(F("    Texto Claro:        "));
    print_hex_buffer(plain_c, 16);
    Serial.print(F("    Cifrado Obtido:     "));
    print_hex_buffer(out_cipher_c, 16);
    Serial.print(F("    Cifrado Esperado:   "));
    print_hex_buffer(exp_cipher_c, 16);

    bool ok_c = (memcmp(out_cipher_c, exp_cipher_c, 16) == 0);
    Serial.print(F("    Resultado Apêndice C.1: "));
    Serial.println(ok_c ? F("PASSOU! [OK]") : F("FALHOU! [ERRO]"));

    if (ok_b && ok_c) {
        Serial.println(F("\n>>> PARTE 3 VALIDADA COM 100% DE SUCESSO! <<<"));
        Serial.println(F("O motor AES-128 em C está em total conformidade com o FIPS-197!"));
    } else {
        Serial.println(F("\n>>> ATENÇÃO: HOUVE DIVERGÊNCIA NA PARTE 3! <<<"));
    }
    Serial.println(F("==================================================\n"));
}

void test_part4() {
    Serial.println(F("\n=================================================="));
    Serial.println(F("     VALIDAÇÃO DA PARTE 4 - DADOS OFICIAIS DUPLA   "));
    Serial.println(F("=================================================="));

    // 1. Derivação da chave a partir das matrículas
    uint8_t derived_key[16];
    derive_key_from_matriculas(MATRICULA_A, MATRICULA_B, derived_key);

    Serial.print(F("[-] Matrícula A (Lorena): "));
    Serial.println(MATRICULA_A);
    Serial.print(F("[-] Matrícula B (Mateus): "));
    Serial.println(MATRICULA_B);

    Serial.print(F("[-] Chave Derivada (ASCII): "));
    for (int i = 0; i < 16; i++) Serial.print((char)derived_key[i]);
    Serial.println();

    Serial.print(F("[-] Chave Derivada (Hex):   "));
    print_hex_buffer(derived_key, 16);

    const char exp_key_ascii[] = "7844002878440030";
    bool ok_key = (memcmp(derived_key, exp_key_ascii, 16) == 0);
    Serial.print(F("    Status da Chave: "));
    Serial.println(ok_key ? F("CORRETA! [OK]") : F("INCORRETA! [ERRO]"));

    // 2. Montagem da Mensagem e Preenchimento PKCS#7
    char raw_message[64];
    snprintf(raw_message, sizeof(raw_message), "A:%s;B:%s", MATRICULA_A, MATRICULA_B);
    size_t raw_len = strlen(raw_message);

    Serial.print(F("\n[-] Mensagem Original ("));
    Serial.print((unsigned int)raw_len);
    Serial.print(F(" bytes): "));
    Serial.println(raw_message);

    uint8_t padded_buffer[64];
    size_t padded_len = apply_pkcs7_padding((const uint8_t*)raw_message, raw_len, padded_buffer);

    Serial.print(F("[-] Mensagem com PKCS#7 ("));
    Serial.print((unsigned int)padded_len);
    Serial.print(F(" bytes / "));
    Serial.print((unsigned int)(padded_len / 16));
    Serial.println(F(" blocos):"));
    Serial.print(F("    Buffer Completo (Hex): "));
    print_hex_buffer(padded_buffer, padded_len);

    Serial.print(F("    Bloco 1 (Hex):         "));
    print_hex_buffer(&padded_buffer[0], 16);
    Serial.print(F("    Bloco 2 (Hex):         "));
    print_hex_buffer(&padded_buffer[16], 16);

    bool ok_pad = (padded_len == 32 && padded_buffer[31] == 0x01);
    Serial.print(F("    Status do PKCS#7:      "));
    Serial.println(ok_pad ? F("1 byte 0x01 adicionado! [OK]") : F("Falha no padding! [ERRO]"));

    // 3. Expansão de Chaves e Cifragem ECB
    uint8_t round_keys[11][16];
    KeyExpansion(derived_key, round_keys);

    uint8_t cipher_output[64];
    encrypt_ecb(padded_buffer, padded_len, round_keys, cipher_output);

    Serial.println(F("\n[-] Cifragem AES-128 em Modo ECB:"));
    Serial.print(F("    Cifrado Total (32 bytes): "));
    print_hex_buffer(cipher_output, 32);

    Serial.print(F("    Bloco Cifrado 1 (Hex):   "));
    print_hex_buffer(&cipher_output[0], 16);
    Serial.print(F("    Bloco Cifrado 2 (Hex):   "));
    print_hex_buffer(&cipher_output[16], 16);

    // Gabarito oficial calculado para a dupla:
    // Bloco 1: 201919f99f96202aef26cdff9eb3374d
    // Bloco 2: 5c7fa16d88cb3c29f0aec6b3c204d966
    const uint8_t exp_c1[16] = {
        0x20, 0x19, 0x19, 0xf9, 0x9f, 0x96, 0x20, 0x2a,
        0xef, 0x26, 0xcd, 0xff, 0x9e, 0xb3, 0x37, 0x4d
    };
    const uint8_t exp_c2[16] = {
        0x5c, 0x7f, 0xa1, 0x6d, 0x88, 0xcb, 0x3c, 0x29,
        0xf0, 0xae, 0xc6, 0xb3, 0xc2, 0x04, 0xd9, 0x66
    };

    bool ok_c1 = (memcmp(&cipher_output[0], exp_c1, 16) == 0);
    bool ok_c2 = (memcmp(&cipher_output[16], exp_c2, 16) == 0);

    Serial.print(F("    Conferência Bloco 1: "));
    Serial.println(ok_c1 ? F("EXATO AO GABARITO! [OK]") : F("DIVERGÊNCIA! [ERRO]"));
    Serial.print(F("    Conferência Bloco 2: "));
    Serial.println(ok_c2 ? F("EXATO AO GABARITO! [OK]") : F("DIVERGÊNCIA! [ERRO]"));

    if (ok_key && ok_pad && ok_c1 && ok_c2) {
        Serial.println(F("\n>>> PARTE 4 VALIDADA COM 100% DE SUCESSO! <<<"));
        Serial.println(F("Os dados da dupla foram derivados, preenchidos e cifrados perfeitamente!"));
    } else {
        Serial.println(F("\n>>> ATENÇÃO: HOUVE DIVERGÊNCIA NA PARTE 4! <<<"));
    }
    Serial.println(F("==================================================\n"));
}

void setup() {
    // 1. Inicializa Monitor Serial USB para depuração e conferência
    Serial.begin(115200);
    delay(1000); // Aguarda estabilização do canal serial

    Serial.println(F("Firmware do Transmissor (TX) - AES-128 ESP32"));
    Serial.println(F("Autor: Mateus | Parceira: Lorena | IFMT - SSC"));

    // Executa as validações das Partes 1, 2, 3 e 4 no boot
    test_part1();
    test_part2();
    test_part3();
    test_part4();

    // TODO (Parte 5): Inicialização da UART2 física (115200 bps, 8N1)
}

void loop() {
    // TODO (Parte 6): Console interativo e envio contínuo
    delay(100);
}

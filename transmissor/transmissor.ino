/*
 * Transmissor (TX) - AES-128 ESP32 (UART2)
 * Disciplina: Segurança de Sistemas de Computação - IFMT
 * Dupla: Lorena Strobel (2023278440028) & Mateus de Souza (2023278440030)
 * Chave: "7844002878440030" | Mensagem: "A:2023278440028;B:2023278440030"
 */

#include <Arduino.h>
#include <stddef.h>
#include <stdint.h>

// -----------------------------------------------------------------------------
// Tabelas e Operações em GF(2^8)
// -----------------------------------------------------------------------------

const uint8_t SBOX[256] PROGMEM = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// Leitura da S-Box na memória Flash (PROGMEM)
uint8_t get_sbox(uint8_t index) { return pgm_read_byte(&SBOX[index]); }

// Multiplicação por {02} em GF(2^8) com redução pelo polinômio 0x1B
uint8_t xtime(uint8_t b) {
  return (uint8_t)((b << 1) ^ (((b >> 7) & 1) * 0x1B));
}

// Mapeamento linear para matriz de estado 4x4 (Column-Major Order)
void bytes_to_state(const uint8_t input[16], uint8_t state[4][4]) {
  for (uint8_t col = 0; col < 4; col++) {
    for (uint8_t row = 0; row < 4; row++) {
      state[row][col] = input[row + 4 * col];
    }
  }
}

// Mapeamento da matriz de estado 4x4 para vetor linear
void state_to_bytes(const uint8_t state[4][4], uint8_t output[16]) {
  for (uint8_t col = 0; col < 4; col++) {
    for (uint8_t row = 0; row < 4; row++) {
      output[row + 4 * col] = state[row][col];
    }
  }
}

// -----------------------------------------------------------------------------
// Primitivas de Rodada do AES-128
// -----------------------------------------------------------------------------

// Adiciona a subchave da rodada ao estado via XOR
void AddRoundKey(uint8_t state[4][4], const uint8_t roundKey[16]) {
  for (uint8_t col = 0; col < 4; col++) {
    for (uint8_t row = 0; row < 4; row++) {
      state[row][col] ^= roundKey[row + 4 * col];
    }
  }
}

// Substituição não-linear byte a byte via S-Box
void SubBytes(uint8_t state[4][4]) {
  for (uint8_t col = 0; col < 4; col++) {
    for (uint8_t row = 0; row < 4; row++) {
      state[row][col] = get_sbox(state[row][col]);
    }
  }
}

// Deslocamento cíclico das linhas do estado para a esquerda
void ShiftRows(uint8_t state[4][4]) {
  // Linha 1: rotação de 1 byte à esquerda
  uint8_t temp1 = state[1][0];
  state[1][0] = state[1][1];
  state[1][1] = state[1][2];
  state[1][2] = state[1][3];
  state[1][3] = temp1;

  // Linha 2: rotação de 2 bytes à esquerda
  uint8_t temp2_0 = state[2][0];
  uint8_t temp2_1 = state[2][1];
  state[2][0] = state[2][2];
  state[2][1] = state[2][3];
  state[2][2] = temp2_0;
  state[2][3] = temp2_1;

  // Linha 3: rotação de 3 bytes à esquerda
  uint8_t temp3 = state[3][3];
  state[3][3] = state[3][2];
  state[3][2] = state[3][1];
  state[3][1] = state[3][0];
  state[3][0] = temp3;
}

// Mistura linear de colunas via multiplicação em GF(2^8)
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

// -----------------------------------------------------------------------------
// Expansão de Chaves e Cifragem de Bloco
// -----------------------------------------------------------------------------

const uint8_t RCON[10] PROGMEM = {0x01, 0x02, 0x04, 0x08, 0x10,
                                  0x20, 0x40, 0x80, 0x1B, 0x36};

uint8_t get_rcon(uint8_t index) { return pgm_read_byte(&RCON[index]); }

// Expansão da chave de 128 bits para 11 subchaves de rodada (176 bytes)
void KeyExpansion(const uint8_t key[16], uint8_t round_keys[11][16]) {
  for (uint8_t i = 0; i < 16; i++) {
    round_keys[0][i] = key[i];
  }

  uint8_t temp[4];

  for (uint8_t i = 4; i < 44; i++) {
    uint8_t prev_rnd = (i - 1) / 4;
    uint8_t prev_col = (i - 1) % 4;

    temp[0] = round_keys[prev_rnd][prev_col * 4 + 0];
    temp[1] = round_keys[prev_rnd][prev_col * 4 + 1];
    temp[2] = round_keys[prev_rnd][prev_col * 4 + 2];
    temp[3] = round_keys[prev_rnd][prev_col * 4 + 3];

    if (i % 4 == 0) {
      // RotWord
      uint8_t t0 = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = t0;

      // SubWord
      temp[0] = get_sbox(temp[0]);
      temp[1] = get_sbox(temp[1]);
      temp[2] = get_sbox(temp[2]);
      temp[3] = get_sbox(temp[3]);

      // XOR com a constante de rodada Rcon
      temp[0] ^= get_rcon((i / 4) - 1);
    }

    uint8_t cur_rnd = i / 4;
    uint8_t cur_col = i % 4;
    uint8_t old_rnd = (i - 4) / 4;
    uint8_t old_col = (i - 4) % 4;

    round_keys[cur_rnd][cur_col * 4 + 0] =
        round_keys[old_rnd][old_col * 4 + 0] ^ temp[0];
    round_keys[cur_rnd][cur_col * 4 + 1] =
        round_keys[old_rnd][old_col * 4 + 1] ^ temp[1];
    round_keys[cur_rnd][cur_col * 4 + 2] =
        round_keys[old_rnd][old_col * 4 + 2] ^ temp[2];
    round_keys[cur_rnd][cur_col * 4 + 3] =
        round_keys[old_rnd][old_col * 4 + 3] ^ temp[3];
  }
}

// Cifragem de um bloco de 16 bytes (10 rodadas do AES-128)
void aes128_encrypt_block(const uint8_t plaintext[16],
                          const uint8_t round_keys[11][16],
                          uint8_t ciphertext[16]) {
  uint8_t state[4][4];
  bytes_to_state(plaintext, state);

  // Rodada 0: Whitening
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

  state_to_bytes(state, ciphertext);
}

// -----------------------------------------------------------------------------
// Preenchimento PKCS#7 e Modo ECB
// -----------------------------------------------------------------------------

// Matrículas oficiais da dupla
const char MATRICULA_A[] = "2023278440028"; // Aluno A: Lorena
const char MATRICULA_B[] = "2023278440030"; // Aluno B: Mateus

// Extrai os 8 últimos dígitos numéricos da matrícula
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
    for (uint8_t i = 0; i < pad; i++)
      out8[i] = '0';
    memcpy(&out8[pad], digits, d_count);
  }
  out8[8] = '\0';
}

// Deriva a chave de 16 bytes a partir dos 8 dígitos finais de cada matrícula
void derive_key_from_matriculas(const char *matA, const char *matB,
                                uint8_t key[16]) {
  char digitsA[9];
  char digitsB[9];
  extract_last_8_digits(matA, digitsA);
  extract_last_8_digits(matB, digitsB);

  memcpy(&key[0], digitsA, 8);
  memcpy(&key[8], digitsB, 8);
}

// Preenchimento PKCS#7 (RFC 5652) para múltiplos de 16 bytes
size_t apply_pkcs7_padding(const uint8_t *in, size_t in_len, uint8_t *out) {
  uint8_t pad_len = 16 - (in_len % 16);
  memcpy(out, in, in_len);
  for (uint8_t i = 0; i < pad_len; i++) {
    out[in_len + i] = pad_len;
  }
  return in_len + pad_len;
}

// Cifragem de múltiplos blocos em modo Electronic Codebook (ECB)
void encrypt_ecb(const uint8_t *padded_data, size_t padded_len,
                 const uint8_t round_keys[11][16], uint8_t *ciphertext) {
  size_t num_blocks = padded_len / 16;
  for (size_t b = 0; b < num_blocks; b++) {
    aes128_encrypt_block(&padded_data[b * 16], round_keys, &ciphertext[b * 16]);
  }
}

// -----------------------------------------------------------------------------
// Driver UART2 e Protocolo de Envio Binário
// -----------------------------------------------------------------------------

#define UART2_RX_PIN 16
#define UART2_TX_PIN 17
#define UART2_BAUD_RATE 115200
#define PROTOCOL_START_BYTE 0xAA

// Imprime buffer em formato hexadecimal
void print_hex_buffer(const uint8_t *buf, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (buf[i] < 0x10)
      Serial.print(F("0"));
    Serial.print(buf[i], HEX);
  }
  Serial.println();
}

// Envia quadro binário [0xAA, num_blocks, payload] via UART2
void send_uart2_frame(uint8_t num_blocks, const uint8_t *ciphertext) {
  size_t total_payload_bytes = (size_t)num_blocks * 16;
  size_t total_frame_bytes = 2 + total_payload_bytes;

  // Envio binário bruto na UART2
  Serial2.write((uint8_t)PROTOCOL_START_BYTE);
  Serial2.write(num_blocks);
  Serial2.write(ciphertext, total_payload_bytes);
  Serial2.flush();

  // Telemetria no Monitor USB Serial
  Serial.println(F("\n--------------------------------------------------"));
  Serial.println(F("[UART2 TX] Quadro binário transmitido com sucesso!"));
  Serial.print(F("[UART2 TX] Configuração: GPIO 17 (TX2) | "));
  Serial.print((unsigned int)UART2_BAUD_RATE);
  Serial.println(F(" bps 8N1"));

  Serial.print(F("[UART2 TX] Frame: "));
  Serial.print((unsigned int)total_frame_bytes);
  Serial.print(F(" bytes (Cabeçalho: 2B | Carga: "));
  Serial.print((unsigned int)total_payload_bytes);
  Serial.println(F("B)"));

  Serial.print(F("[UART2 TX] Marcador: 0xAA | Qtd de Blocos (n): "));
  Serial.println((unsigned int)num_blocks);

  Serial.print(F("[UART2 TX] Payload Cifrado: "));
  print_hex_buffer(ciphertext, total_payload_bytes);
  Serial.println(F("--------------------------------------------------"));
}

// -----------------------------------------------------------------------------
// Autoteste com os Vetores Oficiais NIST FIPS-197 (Apêndices B e C.1)
// -----------------------------------------------------------------------------
bool run_fips197_selftest() {
  Serial.println(F("\n=================================================="));
  Serial.println(F("     VALIDAÇÃO OFICIAL NIST FIPS-197 (AES-128)    "));
  Serial.println(F("=================================================="));

  // Teste 1: NIST FIPS-197 Apêndice B
  const uint8_t key_b[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
  const uint8_t plain_b[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
                               0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
  const uint8_t exp_cipher_b[16] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc,
                                    0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97,
                                    0x19, 0x6a, 0x0b, 0x32};

  uint8_t round_keys_b[11][16];
  KeyExpansion(key_b, round_keys_b);

  uint8_t out_cipher_b[16];
  aes128_encrypt_block(plain_b, round_keys_b, out_cipher_b);

  Serial.println(F("[-] Teste 1: FIPS-197 Apêndice B:"));
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

  // Teste 2: NIST FIPS-197 Apêndice C.1
  const uint8_t key_c[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  const uint8_t plain_c[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                               0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
  const uint8_t exp_cipher_c[16] = {0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b,
                                    0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80,
                                    0x70, 0xb4, 0xc5, 0x5a};

  uint8_t round_keys_c[11][16];
  KeyExpansion(key_c, round_keys_c);

  uint8_t out_cipher_c[16];
  aes128_encrypt_block(plain_c, round_keys_c, out_cipher_c);

  Serial.println(F("\n[-] Teste 2: FIPS-197 Apêndice C.1:"));
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

  bool all_ok = (ok_b && ok_c);
  if (all_ok) {
    Serial.println(
        F("\n>>> AUTOTESTE FIPS-197 VALIDADO COM 100% DE SUCESSO! <<<"));
    Serial.println(
        F("O motor AES-128 em C está em total conformidade com o FIPS-197!"));
  } else {
    Serial.println(
        F("\n>>> ATENÇÃO: HOUVE DIVERGÊNCIA NO AUTOTESTE FIPS-197! <<<"));
  }
  Serial.println(F("==================================================\n"));
  return all_ok;
}

// -----------------------------------------------------------------------------
// Terminal Interativo USB (Console de Comandos)
// -----------------------------------------------------------------------------

static uint8_t current_key[16];
static uint8_t current_round_keys[11][16];
static char current_message[128];

// Cifra e transmite a mensagem ativa via UART2
void process_and_send_message(const char *msg) {
  size_t raw_len = strlen(msg);
  if (raw_len == 0)
    return;
  if (raw_len > 112) {
    Serial.println(F(
        "[ERRO] Mensagem muito extensa! O buffer suporta até 112 caracteres."));
    return;
  }

  // Preenchimento PKCS#7 dinâmico
  uint8_t padded_buffer[128];
  size_t padded_len =
      apply_pkcs7_padding((const uint8_t *)msg, raw_len, padded_buffer);
  uint8_t num_blocks = (uint8_t)(padded_len / 16);

  // Cifragem ECB
  uint8_t ciphertext[128];
  encrypt_ecb(padded_buffer, padded_len, current_round_keys, ciphertext);

  // Telemetria no Monitor USB
  Serial.println(F("\n=================================================="));
  Serial.print(F("[CONSOLE TX] Texto Claro:  \""));
  Serial.print(msg);
  Serial.println(F("\""));

  Serial.print(F("[CONSOLE TX] Tamanho:      "));
  Serial.print((unsigned int)raw_len);
  Serial.print(F(" bytes -> Com PKCS#7: "));
  Serial.print((unsigned int)padded_len);
  Serial.print(F(" bytes ("));
  Serial.print((unsigned int)num_blocks);
  Serial.println(F(" bloco(s) AES)"));

  Serial.print(F("[CONSOLE TX] Chave Atual:   \""));
  for (int i = 0; i < 16; i++)
    Serial.print((char)current_key[i]);
  Serial.println(F("\""));

  Serial.print(F("[CONSOLE TX] Chave Hex:     "));
  print_hex_buffer(current_key, 16);

  // Envio do frame [0xAA, n, ciphertext] via UART2
  send_uart2_frame(num_blocks, ciphertext);
}

// Exibe menu de comandos no Monitor USB
void print_help_menu() {
  Serial.println(
      F("\n================ COMANDOS DO CONSOLE TRANSMISSOR ================"));
  Serial.println(F(
      "  /test               : Reexecuta autoteste dos vetores NIST FIPS-197"));
  Serial.println(F("  /flip               : Inverte 1 bit na chave e reenvia "
                   "(Efeito Avalanche)"));
  Serial.println(
      F("  /key <16_caracteres>: Define uma nova chave simétrica de 128 bits"));
  Serial.println(F("  /reset              : Restaura a chave e mensagem padrão "
                   "das matrículas"));
  Serial.println(F("  /help               : Exibe este menu explicativo"));
  Serial.println(F("  <qualquer_texto>    : Cifra dinamicamente com PKCS#7 e "
                   "envia via UART2"));
  Serial.println(
      F("=================================================================\n"));
}

// Inverte 1 bit da chave para demonstrar o Efeito Avalanche
void handle_cmd_flip() {
  Serial.println(
      F("\n>>> COMANDO /flip: DEMONSTRAÇÃO PRÁTICA DO EFEITO AVALANCHE <<<"));
  uint8_t old_byte = current_key[0];
  current_key[0] ^= 0x01;

  Serial.print(F("[FLIP] Inversão de 1 bit: current_key[0] de 0x"));
  if (old_byte < 0x10)
    Serial.print(F("0"));
  Serial.print(old_byte, HEX);
  Serial.print(F(" para 0x"));
  if (current_key[0] < 0x10)
    Serial.print(F("0"));
  Serial.println(current_key[0], HEX);

  KeyExpansion(current_key, current_round_keys);
  process_and_send_message(current_message);
}

// Define uma nova chave simétrica de 16 caracteres
void handle_cmd_key(const String &arg) {
  if (arg.length() != 16) {
    Serial.print(F("[ERRO] Chave inválida! O AES-128 exige chave de 16 "
                   "bytes/caracteres (recebido: "));
    Serial.print((unsigned int)arg.length());
    Serial.println(F("). A chave não foi alterada."));
    return;
  }

  memcpy(current_key, arg.c_str(), 16);
  KeyExpansion(current_key, current_round_keys);

  Serial.println(F("\n>>> COMANDO /key: NOVA CHAVE SIMÉTRICA CARREGADA! <<<"));
  process_and_send_message(current_message);
}

// Restaura chave e mensagem padrão das matrículas da dupla
void handle_cmd_reset() {
  Serial.println(
      F("\n>>> COMANDO /reset: RESTAURANDO DADOS OFICIAIS DA DUPLA <<<"));

  derive_key_from_matriculas(MATRICULA_A, MATRICULA_B, current_key);
  KeyExpansion(current_key, current_round_keys);
  snprintf(current_message, sizeof(current_message), "A:%s;B:%s", MATRICULA_A,
           MATRICULA_B);

  Serial.print(F("[RESET] Chave oficial restaurada: \""));
  for (int i = 0; i < 16; i++)
    Serial.print((char)current_key[i]);
  Serial.println(F("\""));

  process_and_send_message(current_message);
}

// Reexecuta o autoteste oficial FIPS-197
void handle_cmd_test() {
  Serial.println(F("\n>>> COMANDO /test: REVALIDAÇÃO DOS VETORES OFICIAIS NIST "
                   "FIPS-197 <<<"));
  run_fips197_selftest();
}

// Processa a linha digitada no Monitor USB
void process_serial_input(String input) {
  input.trim();
  if (input.length() == 0)
    return;

  if (input.equalsIgnoreCase(F("/help")) || input.equalsIgnoreCase(F("/?"))) {
    print_help_menu();
  } else if (input.equalsIgnoreCase(F("/test"))) {
    handle_cmd_test();
  } else if (input.equalsIgnoreCase(F("/flip"))) {
    handle_cmd_flip();
  } else if (input.startsWith(F("/key ")) || input.startsWith(F("/KEY "))) {
    String key_arg = input.substring(5);
    key_arg.trim();
    handle_cmd_key(key_arg);
  } else if (input.equalsIgnoreCase(F("/reset"))) {
    handle_cmd_reset();
  } else if (input.startsWith(F("/"))) {
    Serial.print(F("[AVISO] Comando desconhecido: \""));
    Serial.print(input);
    Serial.println(F("\". Digite /help para ver os comandos disponíveis."));
  } else {
    strncpy(current_message, input.c_str(), sizeof(current_message) - 1);
    current_message[sizeof(current_message) - 1] = '\0';
    process_and_send_message(current_message);
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial2.begin(UART2_BAUD_RATE, SERIAL_8N1, UART2_RX_PIN, UART2_TX_PIN);

  Serial.println(F("=================================================="));
  Serial.println(F("  AES-128 ESP32  "));
  Serial.println(F("  Autores: Lorena Strobel | Mateus de Souza  "));
  Serial.println(F("=================================================="));

  // Validação prévia com os vetores NIST FIPS-197
  run_fips197_selftest();

  Serial.println(F(">>> INICIANDO TRANSMISSÃO AUTOMÁTICA DAS MATRÍCULAS <<<"));

  derive_key_from_matriculas(MATRICULA_A, MATRICULA_B, current_key);
  KeyExpansion(current_key, current_round_keys);
  snprintf(current_message, sizeof(current_message), "A:%s;B:%s", MATRICULA_A,
           MATRICULA_B);

  process_and_send_message(current_message);

  print_help_menu();
  Serial.println(
      F("Transmissor pronto. Digite uma mensagem ou comando acima:"));
}

void loop() {
  if (Serial.available() > 0) {
    String input = Serial.readStringUntil('\n');
    process_serial_input(input);
  }
  delay(20);
}

/*
 * ============================================================================
 * PROJETO: AES-128 em Dois ESP32 via UART
 * DISCIPLINA: Segurança de Sistemas de Computação - IFMT
 * 
 * MÓDULO: Transmissor (TX) - Placa A
 * RESPONSÁVEL: Mateus (Aluno A)
 * 
 * DESCRIÇÃO:
 * - Derivação da chave de 16 bytes a partir das matrículas de Mateus e Lorena.
 * - Formatação da mensagem base "A:<matrícula A>;B:<matrícula B>".
 * - Aplicação de preenchimento PKCS#7.
 * - Implementação do AES-128 (SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion).
 * - Cifragem dos blocos de 16 bytes em modo ECB.
 * - Transmissão do quadro binário bruto [0xAA, n, blocos_cifrados] via UART2 (115200 bps, 8N1).
 * ============================================================================
 */

void setup() {
    // TODO: Inicialização do Monitor Serial USB (115200 bps)
    // TODO: Inicialização da UART2 por hardware (115200 bps, 8N1)
}

void loop() {
    // TODO: Rotina de cifragem e envio de dados
}

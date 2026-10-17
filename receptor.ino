/*
 * ============================================================================
 * PROJETO: AES-128 em Dois ESP32 via UART
 * DISCIPLINA: Segurança de Sistemas de Computação - IFMT
 * 
 * MÓDULO: Receptor (RX) - Placa B (Hardware)
 * RESPONSÁVEL PELA CODIFICAÇÃO: Lorena (Aluno A)
 * DUPLA E MATRÍCULAS:
 * - Aluno A: Lorena  (2023278440028) -> 8 dígitos finais: 78440028
 * - Aluno B: Mateus  (2023278440030) -> 8 dígitos finais: 78440030
 * 
 * DADOS CRIPTOGRÁFICOS DERIVADOS:
 * - Chave (16 bytes): "7844002878440030"
 * - Espera receber quadro [0xAA, 0x02, 32 bytes cifrados] via UART2
 * - Decifrar em AES-128 ECB, remover PKCS#7 (1 byte 0x01) e imprimir:
 *   "A:2023278440028;B:2023278440030"
 * ============================================================================
 */

void setup() {
    // TODO: Inicialização do Monitor Serial USB (115200 bps)
    // TODO: Inicialização da UART2 por hardware (115200 bps, 8N1)
}

void loop() {
    // TODO: Máquina de estados de sincronização, recepção e decifragem
}

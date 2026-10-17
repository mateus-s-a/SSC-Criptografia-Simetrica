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

void setup() {
    // TODO: Inicialização do Monitor Serial USB (115200 bps)
    // TODO: Inicialização da UART2 por hardware (115200 bps, 8N1)
}

void loop() {
    // TODO: Rotina de cifragem e envio de dados
}

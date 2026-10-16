/*
 * ============================================================================
 * PROJETO: AES-128 em Dois ESP32 via UART
 * DISCIPLINA: Segurança de Sistemas de Computação - IFMT
 * 
 * MÓDULO: Receptor (RX) - Placa B
 * RESPONSÁVEL: Lorena (Aluno B)
 * 
 * DESCRIÇÃO:
 * - Sincronização no byte de início fixo 0xAA via UART2 (115200 bps, 8N1).
 * - Leitura segura da quantidade de blocos (n) e da carga útil com timeout.
 * - Implementação do AES-128 Inverso (InvSubBytes, InvShiftRows, InvMixColumns, AddRoundKey, KeyExpansion).
 * - Decifragem de cada bloco de 16 bytes em modo ECB.
 * - Validação e descarte do preenchimento PKCS#7.
 * - Exibição da mensagem decifrada em texto claro no Monitor Serial USB.
 * ============================================================================
 */

void setup() {
    // TODO: Inicialização do Monitor Serial USB (115200 bps)
    // TODO: Inicialização da UART2 por hardware (115200 bps, 8N1)
}

void loop() {
    // TODO: Máquina de estados de sincronização, recepção e decifragem
}

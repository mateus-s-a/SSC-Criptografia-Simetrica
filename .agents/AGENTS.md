# Diretrizes Centrais para Agentes no Projeto AES-128 ESP32

Este repositório contém o projeto prático da disciplina de **Segurança de Sistemas de Computação** (Criptografia Simétrica), desenvolvido pela dupla **Mateus e Lorena**, com prazo final de entrega até **19/10 às 23h59**.

## Identificação e Matrículas da Dupla:
- **Aluno A**: Lorena — Matrícula: `2023278440028` (8 últimos dígitos: `78440028`)
- **Aluno B**: Mateus — Matrícula: `2023278440030` (8 últimos dígitos: `78440030`)

## Divisão de Responsabilidades da Dupla:
- **Mateus (Aluno B)**: Responsável primário pela codificação do **Transmissor (TX / Placa A)** no sketch `transmissor.ino` (derivação da chave, preenchimento PKCS#7, cifragem AES-128 ECB e envio do frame binário bruto via UART2).
- **Lorena (Aluno A)**: Responsável primária pela codificação do **Receptor (RX / Placa B)** no sketch `receptor.ino` (sincronização no `0xAA`, recepção com timeout, decifragem AES-128 ECB inversa, remoção de PKCS#7 e saída no Monitor Serial USB).
- **Relatório Final**: Elaboração conjunta (formato e fluxo em definição pela dupla).

## Estratégia de Operação do Transmissor (Opção B - Modo Duplo Interativo):
1. **Envio Automático Inicial**:
   - Ao inicializar o ESP32 (`setup()`), o firmware deriva a chave oficial (`7844002878440030`), monta a mensagem padrão da dupla (`A:2023278440028;B:2023278440030`), aplica o preenchimento PKCS#7 (1 byte `0x01`), cifra os 2 blocos em AES-128 ECB e transmite o quadro binário bruto `[0xAA, 0x02, 32 bytes]` pela UART2.
2. **Console Interativo via USB Serial (`loop()`):**
   - O `transmissor.ino` escuta continuamente a porta serial USB (`Serial`).
   - Se o usuário (ou o professor na arguição) digitar qualquer novo texto:
     - O ESP32 calcula o preenchimento PKCS#7 correspondente dinamicamente, cifra em $n$ blocos AES-128 ECB e transmite pela UART2.
   - Suporte a comandos especiais para a arguição prática do professor:
     - `/flip`: inverte 1 bit na chave e reenvia a mensagem para demonstrar o Efeito Avalanche ao vivo.
     - `/key <chave_16_bytes>`: atualiza a chave simétrica dinamicamente para testar chaves propostas pelo professor.
     - `/reset`: restaura a chave e mensagem padrão das matrículas.

## Regras Críticas de Conduta do Agente:
1. **NUNCA introduzir bibliotecas criptográficas externas** (como `mbedtls`, `tinycrypt`, etc.) no código-fonte final C/C++ dos ESP32. O AES-128 deve ser 100% implementado do zero.
2. **Respeitar os Vetores FIPS-197**: Qualquer alteração no motor criptográfico em C/C++ deve ser previamente validada contra os vetores oficiais dos Apêndices B e C.1 do NIST FIPS-197.
3. **Respeitar o Protocolo UART**: O envio pela UART2 deve ser obrigatoriamente em **bytes binários brutos** (`write`), nunca texto hexadecimal. O quadro segue o formato `[0xAA, n, blocos_cifrados]`.
4. **Respeitar as Regras de Matrícula**: A chave e a mensagem devem seguir estritamente o algoritmo de derivação dos 8 dígitos finais das matrículas dos integrantes Mateus e Lorena.
5. **Preparação para Arguição Cruzada**: Manter o código de TX e RX claro, modular e amplamente documentado, pois Mateus precisará explicar o código do RX (de Lorena) e Lorena precisará explicar o código do TX (de Mateus), além de serem desafiados com alterações ao vivo.

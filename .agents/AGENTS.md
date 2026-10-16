# Diretrizes Centrais para Agentes no Projeto AES-128 ESP32

Este repositório contém o projeto prático da disciplina de **Segurança de Sistemas de Computação** (Criptografia Simétrica), desenvolvido pela dupla **Mateus e Lorena**, com prazo final de entrega até **19/10 às 23h59**.

## Divisão de Responsabilidades da Dupla:
- **Mateus (Aluno A)**: Responsável primário pela codificação do **Transmissor (TX - Placa A)** (preenchimento PKCS#7, cifragem AES-128 ECB e envio do frame binário bruto via UART2).
- **Lorena (Aluno B)**: Responsável primária pela codificação do **Receptor (RX - Placa B)** (sincronização no `0xAA`, recepção com timeout, decifragem AES-128 ECB inversa, remoção de PKCS#7 e saída no Monitor Serial USB).
- **Relatório Final**: Elaboração conjunta (formato e fluxo em definição pela dupla).

## Regras Críticas de Conduta do Agente:
1. **NUNCA introduzir bibliotecas criptográficas externas** (como `mbedtls`, `tinycrypt`, etc.) no código-fonte final C/C++ dos ESP32. O AES-128 deve ser 100% implementado do zero.
2. **Respeitar os Vetores FIPS-197**: Qualquer alteração no motor criptográfico em C/C++ deve ser previamente validada contra os vetores oficiais dos Apêndices B e C.1 do NIST FIPS-197.
3. **Respeitar o Protocolo UART**: O envio pela UART2 deve ser obrigatoriamente em **bytes binários brutos** (`write`), nunca texto hexadecimal. O quadro segue o formato `[0xAA, n, blocos_cifrados]`.
4. **Respeitar as Regras de Matrícula**: A chave e a mensagem devem seguir estritamente o algoritmo de derivação dos 8 dígitos finais das matrículas dos integrantes Mateus e Lorena.
5. **Preparação para Arguição Cruzada**: Manter o código de TX e RX claro, modular e amplamente documentado, pois Mateus precisará explicar o código do RX (de Lorena) e Lorena precisará explicar o código do TX (de Mateus), além de serem desafiados com alterações ao vivo.

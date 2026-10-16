# Diretrizes Gerais e Restrições do Professor

## Metadados do Trabalho
- **Disciplina**: Segurança de Sistemas de Computação — Criptografia Simétrica
- **Dupla**: 
  - **Mateus (Aluno A)**: Responsável pela codificação do Transmissor (TX / Placa A).
  - **Lorena (Aluno B)**: Responsável pela codificação do Receptor (RX / Placa B).
  - **Relatório**: Elaboração e formato final em processo de definição pela dupla.
- **Data e Horário Limite de Entrega**: **19/10 até às 23h59**
- **Documento Base**: `utils/Trabalho_AES-128_ESP32.pdf`

---

## 1. Proibição Estrita de Bibliotecas Criptográficas
- **Regra Fundamental**: A implementação do AES-128 deve ser feita **100% do zero** em linguagem C/C++ (ambiente ESP32 / Arduino / PlatformIO).
- **Proibição de mbedTLS / TinyCrypt / OpenSSL no Firmware**: É expressamente proibido o uso de qualquer biblioteca externa de criptografia no código-fonte final entregue para o transmissor ou receptor.
- **Uso de mbedTLS / Libs externas**: Permitido **estritamente em scripts de bancada/testes locais** (ex: Python ou teste offline no PC) para checar e validar resultados. Nenhum `#include <mbedtls/...>` ou similar pode estar presente no código embarcado final entregue.

---

## 2. Entregáveis Obrigatórios
1. **Código-Fonte Comentado**:
   - Firmware do Transmissor (ESP32 - Placa A).
   - Firmware do Receptor (ESP32 - Placa B).
   - O código deve ser extensamente comentado, modular e hospedado em repositório GitHub.
2. **Relatório Técnico Curto**:
   - Extensão máxima: **até 4 páginas**.
   - Conteúdo obrigatório: Registros hexadecimais da Etapa 3, detalhamento dos 5 estados intermediários do Bloco 1 (Rodada 1), cálculo do Efeito Avalanche e discussão técnica aprofundada sobre a insegurança do modo ECB.
3. **Apresentação Oral e Demonstração Prática**:
   - Demonstração ao vivo em bancada com os dois ESP32 comunicando-se via UART2.
   - Explicação cruzada: cada integrante da dupla deve ser capaz de explicar o trecho de código implementado pelo colega.
   - Arguição com modificação em tempo real pelo professor (ex: alteração de mensagem ou bit da chave).

---

## 3. Uso de Ferramentas de IA
- O uso de ferramentas de Inteligência Artificial é **permitido exclusivamente como apoio ao estudo, raciocínio e depuração**.
- A dupla é integralmente responsável por compreender, dominar, justificar linha por linha e executar as alterações propostas na arguição oral perante o professor.

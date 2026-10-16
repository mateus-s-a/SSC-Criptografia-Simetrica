# Banco de Perguntas e Respostas para Arguição com o Professor

## 1. Origem Matemática da S-Box
- **Pergunta do Professor**: *"A S-Box está implementada como uma tabela constante na memória. De onde vieram esses valores e qual o papel dela no algoritmo?"*
- **Resposta Técnica**:
  - A S-Box é a **única etapa não-linear** do AES, sendo a responsável direta pela propriedade de **confusão** (quebrar a relação estatística entre o texto claro e a chave).
  - Ela é gerada em duas etapas algébricas bem definidas:
    1. **Inverso Multiplicativo no Corpo de Galois $GF(2^8)$**: Cada byte é interpretado como um elemento do corpo finito gerado pelo polinômio irredutível $m(x) = x^8 + x^4 + x^3 + x + 1$ (representado pelo byte `0x11B`). Calcula-se o inverso $b^{-1}$ tal que $b \cdot b^{-1} \equiv 1 \pmod{m(x)}$, definindo por convenção que $0^{-1} = 0$.
    2. **Transformação Afim sobre $GF(2)$**: O byte resultante da inversão é multiplicado por uma matriz binária fixa $8 \times 8$ invertível e somado (XOR) com a constante fixa `0x63`. Isso elimina pontos fixos e propriedades algébricas simples que poderiam ser exploradas por criptoanálise diferencial ou linear.

---

## 2. A Operação `xtime` e Multiplicação em $GF(2^8)$
- **Pergunta do Professor**: *"Como funciona a função `xtime` e por que ela é necessária no MixColumns?"*
- **Resposta Técnica**:
  - A transformação `MixColumns` multiplica cada coluna da matriz de estado por uma matriz polinomial cujos coeficientes são $\{02\}$ e $\{03\}$.
  - Em $GF(2^8)$, multiplicar por $\{02\}$ equivale a multiplicar pelo monômio $x$. Em nível binário, isso é um deslocamento à esquerda de 1 bit (`b << 1`).
  - Se o bit mais significativo (MSB) do byte original for 1, a multiplicação transborda do grau 7 para o grau 8. Como estamos no corpo quociente $GF(2)[x] / (x^8 + x^4 + x^3 + x + 1)$, subtrair/somar (XOR) o polinômio redutor reduz o valor. Como $x^8 \equiv x^4 + x^3 + x + 1$, fazemos XOR com `0x1B`.
  - A fórmula compacta da `xtime` é:
    ```c
    uint8_t xtime(uint8_t b) {
        return ((b << 1) ^ (((b >> 7) & 1) * 0x1B));
    }
    ```
  - E para multiplicar por $\{03\}$, usamos a distributividade: $\{03\} \cdot b = (\{02\} \oplus \{01\}) \cdot b = \text{xtime}(b) \oplus b$.

---

## 3. Papel de ShiftRows e MixColumns (Difusão)
- **Pergunta do Professor**: *"Por que precisamos de ShiftRows E MixColumns? Por que apenas um deles não é suficiente?"*
- **Resposta Técnica**:
  - Ambos atuam em conjunto para criar a propriedade de **difusão** (espalhar a influência de um único bit do texto claro ou da chave por todo o bloco cifrado).
  - `SubBytes` atua byte a byte de forma isolada (sem difusão entre posições).
  - `MixColumns` mistura bytes dentro da **mesma coluna**, mas não propaga dados entre colunas diferentes.
  - `ShiftRows` translada os bytes entre diferentes colunas.
  - A combinação `ShiftRows + MixColumns` garante que, após apenas duas rodadas, cada byte do estado intermediário dependa de todos os 16 bytes do estado inicial.

---

## 4. O Efeito Avalanche
- **Pergunta do Professor**: *"O que é o efeito avalanche e por que esperamos em torno de 50% de alteração de bits?"*
- **Resposta Técnica**:
  - Uma boa cifra de bloco deve simular uma permutação pseudoaleatória.
  - Se um único bit do texto claro ou da chave for invertido (distância de Hamming = 1), cada um dos 128 bits de saída deve ter uma probabilidade de $50\%$ de mudar de valor (independente dos outros bits).
  - Por isso, em média, esperamos que aproximadamente 64 bits (de 128) sofram alteração (~50%). Se o valor ficasse próximo de 0% ou 100%, haveria vazamento de correlação linear identificável por criptoanalistas.

---

## 5. Falhas do Modo ECB e Espionagem na UART
- **Pergunta do Professor**: *"Se um espião monitorar o barramento UART2 e capturar os pacotes `0xAA 0x02 ...`, o que ele pode descobrir e como pode atacar o sistema?"*
- **Resposta Técnica**:
  - No ECB, cada bloco de 16 bytes é cifrado independentemente: $C_i = E_K(P_i)$.
  - **Vazamento de Padrão**: Se os blocos de texto claro forem iguais (como `"LIGAR LED VERDE."`), os criptogramas serão idênticos (`e0c22a6f02664f487dc9528642203dec`). O espião aprende quando um comando se repete.
  - **Ataque de Replay**: O espião não precisa quebrar a chave AES; ele simplesmente captura o frame que fez o LED acender e o reinjeta na linha RX do ESP32 receptor em momento posterior.
  - **Substituição de Blocos**: O espião pode substituir o bloco do comando "DESLIGAR" pelo bloco do comando "LIGAR".
  - **Como solucionar**: Adotando CBC ou CTR com um IV/Nonce aleatório gerado a cada pacote, ou de forma ideal, o modo GCM, que inclui autenticação (MAC/Tag) contra qualquer injeção ou modificação.

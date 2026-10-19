# Especificação dos Cálculos Matemáticos do Transmissor (TX — AES-128)

Este documento descreve detalhadamente todos os **cálculos matemáticos, transformações matriciais e derivações criptográficas** executados pelo firmware do **Transmissor (TX)** ([`transmissor/transmissor.ino`](file:///home/spacery/Documents/[CodeRoot]/IFMT/Segurança-Sistemas-Computacionais/SSC-Criptografia-Simetrica/transmissor/transmissor.ino)), implementado por **Mateus de Souza (Aluno B)** em conjunto com **Lorena Strobel (Aluno A)** para a disciplina de Segurança de Sistemas de Computação do IFMT.

Os cálculos a seguir utilizam estritamente o cenário oficial das **matrículas da dupla** definido no enunciado do projeto ([`utils/Trabalho_AES-128_ESP32.pdf`](file:///home/spacery/Documents/[CodeRoot]/IFMT/Segurança-Sistemas-Computacionais/SSC-Criptografia-Simetrica/utils/Trabalho_AES-128_ESP32.pdf)).

---

## 1. Dados de Entrada e Derivação Inicial

### 1.1. Matrículas e Chave Simétrica Mestre
Conforme a regra do projeto, a chave simétrica de 128 bits (16 bytes) é formada pela concatenação dos **8 últimos dígitos** da matrícula de Lorena (Aluno A) e de Mateus (Aluno B):

* **Lorena (Aluno A)**: Matrícula `2023278440028` $\rightarrow$ 8 últimos dígitos: `78440028`
* **Mateus (Aluno B)**: Matrícula `2023278440030` $\rightarrow$ 8 últimos dígitos: `78440030`

$$\text{Chave (ASCII)} = \text{"7844002878440030"}$$

Mapeamento caractere para hexadecimal (tabela ASCII):

| Byte | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **ASCII** | `'7'` | `'8'` | `'4'` | `'4'` | `'0'` | `'0'` | `'2'` | `'8'` | `'7'` | `'8'` | `'4'` | `'4'` | `'0'` | `'0'` | `'3'` | `'0'` |
| **Hex** | `37` | `38` | `34` | `34` | `30` | `30` | `32` | `38` | `37` | `38` | `34` | `34` | `30` | `30` | `33` | `30` |

$$\text{Chave Hex} = \mathtt{37383434303032383738343430303330}_{16}$$

---

### 1.2. Mensagem em Texto Claro da Dupla
A mensagem enviada no cenário padrão contém a identificação de ambos os alunos com suas matrículas integrais:

$$\text{Texto Claro} = \text{"A:2023278440028;B:2023278440030"}$$

Comprimento original: **31 caracteres (31 bytes)**.

Representação hexadecimal bruta (31 bytes):
```text
41 3a 32 30 32 33 32 37 38 34 34 30 30 32 38 3b 42 3a 32 30 32 33 32 37 38 34 34 30 30 33 30
 A  :  2  0  2  3  2  7  8  4  4  0  0  2  8  ;  B  :  2  0  2  3  2  7  8  4  4  0  0  3  0
```

---

## 2. Preenchimento PKCS#7 e Divisão em Blocos

O algoritmo AES-128 opera exclusivamente sobre blocos de tamanho fixo de **128 bits (16 bytes)**. Como a mensagem possui 31 bytes, ela não é múltiplo de 16.

### 2.1. Cálculo do Padding PKCS#7
A norma PKCS#7 (RFC 5652) define que o número de bytes de preenchimento $P$ é dado por:

$$P = 16 - (\text{comprimento} \pmod{16})$$
$$P = 16 - (31 \pmod{16}) = 16 - 15 = 1 \text{ byte}$$

O valor de cada byte de preenchimento deve ser rigorosamente igual à quantidade de bytes adicionados. Portanto, adiciona-se **1 byte de valor `0x01`**:

$$\text{Mensagem Padded (32 bytes)} = \text{"A:2023278440028;B:2023278440030"} \,\|\, \mathtt{0x01}$$

Hexadecimal completo com preenchimento (32 bytes):
```text
41 3a 32 30 32 33 32 37 38 34 34 30 30 32 38 3b 42 3a 32 30 32 33 32 37 38 34 34 30 30 33 30 01
```

### 2.2. Divisão em Blocos de 16 Bytes
* **Bloco 0 (Bytes 0 a 15)**:
  ```text
  ASCII: "A:2023278440028;"
  Hex:   41 3a 32 30 32 33 32 37 38 34 34 30 30 32 38 3b
  ```
* **Bloco 1 (Bytes 16 a 31)**:
  ```text
  ASCII: "B:2023278440030" + 0x01
  Hex:   42 3a 32 30 32 33 32 37 38 34 34 30 30 33 30 01
  ```

---

## 3. Expansão de Chave (*KeyExpansion*)

O AES-128 requer **11 subchaves de 16 bytes** (uma para o *whitening* inicial na Rodada 0 e dez para as Rodadas 1 a 10). Isso equivale a um vetor linear de **44 palavras de 32 bits** ($w[0]$ a $w[43]$), totalizando 176 bytes.

### 3.1. Palavras Iniciais ($w[0]$ a $w[3]$)
As 4 primeiras palavras recebem os 16 bytes da chave mestre:
* $w[0] = [37, 38, 34, 34]$
* $w[1] = [30, 30, 32, 38]$
* $w[2] = [37, 38, 34, 34]$
* $w[3] = [30, 30, 33, 30]$

### 3.2. Regra Geral de Geração ($w[i]$ para $i \ge 4$)
Para cada palavra $w[i]$:
* Se $i \pmod 4 \ne 0$:
  $$w[i] = w[i-4] \oplus w[i-1]$$
* Se $i \pmod 4 = 0$ (início de uma nova subchave de rodada):
  $$w[i] = w[i-4] \oplus \left(\text{SubWord}(\text{RotWord}(w[i-1])) \oplus \text{Rcon}[i/4]\right)$$

Onde:
* **`RotWord`**: Rotação cíclica de 1 byte à esquerda: $[b_0, b_1, b_2, b_3] \rightarrow [b_1, b_2, b_3, b_0]$.
* **`SubWord`**: Aplicação da S-Box do Rijndael a cada um dos 4 bytes.
* **`Rcon`**: Constante de rodada aplicada apenas ao primeiro byte da palavra:
  $$\text{Rcon} = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]$$

---

### 3.3. Cálculo Detalhado da Primeira Nova Subchave (Rodada 1: $w[4 \dots 7]$)

#### Cálculo de $w[4]$ (Índice $i = 4$, múltiplo de 4):
1. **Palavra anterior $w[3]$**:
   $$w[3] = [30, 30, 33, 30]$$
2. **`RotWord(w[3])`**:
   $$\text{RotWord}([30, 30, 33, 30]) = [30, 33, 30, 30]$$
3. **`SubWord` (Consulta na S-Box)**:
   * $\text{S-Box}[0x30] = 0x04$
   * $\text{S-Box}[0x33] = 0xC3$
   * $\text{S-Box}[0x30] = 0x04$
   * $\text{S-Box}[0x30] = 0x04$
   $$\text{SubWord} = [04, C3, 04, 04]$$
4. **Aplicação de $\text{Rcon}[4/4] = \text{Rcon}[1] = [01, 00, 00, 00]$**:
   $$\text{Temp} = [04 \oplus 01, C3 \oplus 00, 04 \oplus 00, 04 \oplus 00] = [05, C3, 04, 04]$$
5. **XOR com $w[i-4] = w[0] = [37, 38, 34, 34]$**:
   $$w[4] = [37 \oplus 05, 38 \oplus C3, 34 \oplus 04, 34 \oplus 04] = [32, FB, 30, 30]$$

#### Cálculo de $w[5], w[6], w[7]$:
* $w[5] = w[1] \oplus w[4] = [30, 30, 32, 38] \oplus [32, FB, 30, 30] = [02, CB, 02, 08]$
* $w[6] = w[2] \oplus w[5] = [37, 38, 34, 34] \oplus [02, CB, 02, 08] = [35, F3, 36, 3C]$
* $w[7] = w[3] \oplus w[6] = [30, 30, 33, 30] \oplus [35, F3, 36, 3C] = [05, C3, 05, 0C]$

---

### 3.4. Matrizes de Subchave da Rodada 0 e da Rodada 1
No AES, as 4 palavras de 32 bits de cada subchave são organizadas em matrizes $4 \times 4$ **coluna por coluna**:

$$\text{Subchave 0} = \begin{bmatrix} w[0] & w[1] & w[2] & w[3] \end{bmatrix} = \begin{bmatrix} 37 & 30 & 37 & 30 \\ 38 & 30 & 38 & 30 \\ 34 & 32 & 34 & 33 \\ 34 & 38 & 34 & 30 \end{bmatrix}$$

$$\text{Subchave 1} = \begin{bmatrix} w[4] & w[5] & w[6] & w[7] \end{bmatrix} = \begin{bmatrix} 32 & 02 & 35 & 05 \\ FB & CB & F3 & C3 \\ 30 & 02 & 36 & 05 \\ 30 & 08 & 3C & 0C \end{bmatrix}$$

---

## 4. Cifragem Detalhada do Bloco 0 (Rodada 1 Completa)

Apresentamos agora os **cinco estados intermediários obrigatórios** da primeira rodada de cifragem sobre o Bloco 0, conforme exigência do relatório técnico da disciplina.

### Estado Inicial (Entrada do Bloco 0)
O Bloco 0 (`"A:2023278440028;"`) é carregado coluna por coluna na matriz de estado $4 \times 4$:

$$\text{Estado Inicial} = \begin{bmatrix} 41 & 32 & 38 & 30 \\ 3A & 33 & 34 & 32 \\ 32 & 32 & 34 & 38 \\ 30 & 37 & 30 & 3B \end{bmatrix}$$

---

### (1) Estado 1: Após `AddRoundKey` Inicial (Rodada 0 — *Whitening*)
Realiza a operação $\text{Estado} \oplus \text{Subchave 0}$:

$$\text{Estado 1} = \begin{bmatrix} 41 \oplus 37 & 32 \oplus 30 & 38 \oplus 37 & 30 \oplus 30 \\ 3A \oplus 38 & 33 \oplus 30 & 34 \oplus 38 & 32 \oplus 30 \\ 32 \oplus 34 & 32 \oplus 32 & 34 \oplus 34 & 38 \oplus 33 \\ 30 \oplus 34 & 37 \oplus 38 & 30 \oplus 34 & 3B \oplus 30 \end{bmatrix} = \begin{bmatrix} 76 & 02 & 0F & 00 \\ 02 & 03 & 0C & 02 \\ 06 & 00 & 00 & 0B \\ 04 & 0F & 04 & 0B \end{bmatrix}$$

Vetor linear do Estado 1: `76 02 06 04 02 03 00 0f 0f 0c 00 04 00 02 0b 0b`

---

### (2) Estado 2: Após `SubBytes`
Cada byte da matriz de estado é substituído pelo valor correspondente na **S-Box** do Rijndael.

*Exemplos de substituição direta na tabela:*
* $\text{S-Box}[0x76] = 0x38$
* $\text{S-Box}[0x02] = 0x77$
* $\text{S-Box}[0x06] = 0x6F$
* $\text{S-Box}[0x04] = 0xF2$
* $\text{S-Box}[0x03] = 0x7B$
* $\text{S-Box}[0x0F] = 0x76$
* $\text{S-Box}[0x0C] = 0xFE$
* $\text{S-Box}[0x00] = 0x63$
* $\text{S-Box}[0x0B] = 0x2B$

Aplicando a todos os 16 elementos:

$$\text{Estado 2} = \begin{bmatrix} 38 & 77 & 76 & 63 \\ 77 & 7B & FE & 77 \\ 6F & 63 & 63 & 2B \\ F2 & 76 & F2 & 2B \end{bmatrix}$$

Vetor linear do Estado 2: `38 77 6f f2 77 7b 63 76 76 fe 63 f2 63 77 2b 2b`

---

### (3) Estado 3: Após `ShiftRows`
As linhas da matriz de estado sofrem deslocamento cíclico para a **esquerda**:
* **Linha 0**: Desloca 0 posições $\rightarrow [38, 77, 76, 63]$
* **Linha 1**: Desloca 1 posição $\rightarrow [7B, FE, 77, 77]$
* **Linha 2**: Desloca 2 posições $\rightarrow [63, 2B, 6F, 63]$
* **Linha 3**: Desloca 3 posições $\rightarrow [2B, F2, 76, F2]$

$$\text{Estado 3} = \begin{bmatrix} 38 & 77 & 76 & 63 \\ 7B & FE & 77 & 77 \\ 63 & 2B & 6F & 63 \\ 2B & F2 & 76 & F2 \end{bmatrix}$$

Vetor linear do Estado 3: `38 7b 63 2b 77 fe 2b f2 76 77 6f 76 63 77 63 f2`

---

### (4) Estado 4: Após `MixColumns`
Cada coluna do estado é multiplicada pela matriz fixa de coeficientes polinomiais no corpo de Galois $GF(2^8)$ com polinômio redutor $P(x) = x^8 + x^4 + x^3 + x + 1$ (`0x11B`):

$$\begin{bmatrix} s'_{0,c} \\ s'_{1,c} \\ s'_{2,c} \\ s'_{3,c} \end{bmatrix} = \begin{bmatrix} 02 & 03 & 01 & 01 \\ 01 & 02 & 03 & 01 \\ 01 & 01 & 02 & 03 \\ 03 & 01 & 01 & 02 \end{bmatrix} \begin{bmatrix} s_{0,c} \\ s_{1,c} \\ s_{2,c} \\ s_{3,c} \end{bmatrix}$$

#### Demonstração Matemática do Cálculo da Coluna 0:
Entrada da Coluna 0: $s_0 = 0x38$, $s_1 = 0x7B$, $s_2 = 0x63$, $s_3 = 0x2B$.

A função de multiplicação por 2 no $GF(2^8)$ opera via `xtime`:
* $\text{xtime}(0x38)$: como o bit mais significativo é 0 ($0x38 < 0x80$), $\text{xtime}(0x38) = 0x38 \ll 1 = 0x70$.
* $\text{xtime}(0x7B) = 0x7B \ll 1 = 0xF6$.
* $\{03\} \cdot b = \text{xtime}(b) \oplus b \implies \{03\} \cdot 0x7B = 0xF6 \oplus 0x7B = 0x8D$.
* $\text{xtime}(0x63) = 0x63 \ll 1 = 0xC6$.
* $\text{xtime}(0x2B) = 0x2B \ll 1 = 0x56$.
* $\{03\} \cdot 0x2B = 0x56 \oplus 0x2B = 0x7D$.
* $\{03\} \cdot 0x38 = 0x70 \oplus 0x38 = 0x48$.

Calculando cada elemento resultante da Coluna 0:
* $s'_{0,0} = (\{02\} \cdot 38) \oplus (\{03\} \cdot 7B) \oplus 63 \oplus 2B = 70 \oplus 8D \oplus 63 \oplus 2B = \mathbf{B5}_{16}$
* $s'_{1,0} = 38 \oplus (\{02\} \cdot 7B) \oplus (\{03\} \cdot 63) \oplus 2B = 38 \oplus F6 \oplus A5 \oplus 2B = \mathbf{40}_{16}$
* $s'_{2,0} = 38 \oplus 7B \oplus (\{02\} \cdot 63) \oplus (\{03\} \cdot 2B) = 38 \oplus 7B \oplus C6 \oplus 7D = \mathbf{F8}_{16}$
* $s'_{3,0} = (\{03\} \cdot 38) \oplus 7B \oplus 63 \oplus (\{02\} \cdot 2B) = 48 \oplus 7B \oplus 63 \oplus 56 = \mathbf{06}_{16}$

Coluna 0 resultante: $[B5, 40, F8, 06]^T$.

Repetindo o cálculo para as colunas 1, 2 e 3, obtemos a matriz completa:

$$\text{Estado 4} = \begin{bmatrix} B5 & 2E & 6C & CE \\ 40 & 1F & 5F & DA \\ F8 & D2 & 45 & DF \\ 06 & B3 & 6E & 4E \end{bmatrix}$$

Vetor linear do Estado 4: `b5 40 f8 06 2e 1f d2 b3 6c 5f 45 6e ce da df 4e`

---

### (5) Estado 5: Após `AddRoundKey` (com Subchave 1)
Realiza a operação $\text{Estado 4} \oplus \text{Subchave 1}$:

$$\text{Estado 5} = \begin{bmatrix} B5 \oplus 32 & 2E \oplus 02 & 6C \oplus 35 & CE \oplus 05 \\ 40 \oplus FB & 1F \oplus CB & 5F \oplus F3 & DA \oplus C3 \\ F8 \oplus 30 & D2 \oplus 02 & 45 \oplus 36 & DF \oplus 05 \\ 06 \oplus 30 & B3 \oplus 08 & 6E \oplus 3C & 4E \oplus 0C \end{bmatrix} = \begin{bmatrix} 87 & 2C & 59 & CB \\ BB & D4 & AC & 19 \\ C8 & D0 & 73 & DA \\ 36 & BB & 52 & 42 \end{bmatrix}$$

Vetor linear do Estado 5: `87 bb c8 36 2c d4 d0 bb 59 ac 73 52 cb 19 da 42`

---

### 4.1. Resumo dos 5 Estados Intermediários (Tabela Oficial)

| Etapa da Rodada 1 | Representação Hexadecimal Linear (16 bytes) |
| :--- | :--- |
| **(1) Após `AddRoundKey` Inicial (Chave 0)** | `76 02 06 04 02 03 00 0f 0f 0c 00 04 00 02 0b 0b` |
| **(2) Após `SubBytes`** | `38 77 6f f2 77 7b 63 76 76 fe 63 f2 63 77 2b 2b` |
| **(3) Após `ShiftRows`** | `38 7b 63 2b 77 fe 2b f2 76 77 6f 76 63 77 63 f2` |
| **(4) Após `MixColumns`** | `b5 40 f8 06 2e 1f d2 b3 6c 5f 45 6e ce da df 4e` |
| **(5) Após `AddRoundKey` (Chave 1)** | `87 bb c8 36 2c d4 d0 bb 59 ac 73 52 cb 19 da 42` |

---

## 5. Cifragem dos Blocos e Texto Cifrado Final (Modo ECB)

As rodadas 2 a 9 continuam executando as 4 transformações de forma encadeada. Na **Rodada 10 final**, a etapa `MixColumns` é suprimida por definição do NIST FIPS-197, executando apenas `SubBytes`, `ShiftRows` e `AddRoundKey(Subchave 10)`.

### 5.1. Saída do Bloco 0 (16 bytes)
$$\text{Cifrado Bloco 0} = \mathtt{201919f99f96202aef26cdff9eb3374d}_{16}$$

### 5.2. Saída do Bloco 1 (16 bytes)
O Bloco 1 (`"B:2023278440030" + 0x01`) é processado pelas mesmas 10 rodadas com a mesma chave:
$$\text{Cifrado Bloco 1} = \mathtt{5c7fa16d88cb3c29f0aec6b3c204d966}_{16}$$

### 5.3. Texto Cifrado Completo (32 bytes)
Concatenando os dois blocos cifrados:

$$\text{Carga Cifrada Total} = \mathtt{201919f99f96202aef26cdff9eb3374d5c7fa16d88cb3c29f0aec6b3c204d966}_{16}$$

---

## 6. Análise Matemática do Efeito Avalanche

O **Efeito Avalanche** é a propriedade criptográfica fundamental segundo a qual uma alteração ínfima na entrada (chave ou texto em claro) deve provocar uma alteração estatisticamente imprevisível em aproximadamente **50% dos bits** do texto cifrado.

A distância de Hamming $H(C_1, C_2)$ entre dois blocos cifrados de 128 bits é calculada contando os bits em nível alto da operação XOR:

$$H(C_1, C_2) = \sum_{j=0}^{127} (C_{1}[j] \oplus C_{2}[j])$$

### 6.1. Inversão de 1 bit na Mensagem em Claro
* Texto Original (Bloco 0): `"A:2023278440028;"`
* Texto com 1 bit invertido no primeiro caractere (`'A'` = `0x41` $\rightarrow$ `'@'` = `0x40`):
  * Cifrado Original: `201919f99f96202aef26cdff9eb3374d`
  * Cifrado Alterado:  `7f9a4db4093abb1db57614f32778a3ce`
* **Diferença de bits**: **63 de 128 bits** divergentes
* **Porcentagem**: $$\frac{63}{128} \times 100\% = \mathbf{49{,}22\%}$$

### 6.2. Inversão de 1 bit na Chave Simétrica (Comando `/flip`)
* Chave Original: `"7844002878440030"` (primeiro byte `0x37`)
* Chave com 1 bit invertido (primeiro byte `0x37` $\oplus$ `0x01` = `0x36` $\rightarrow$ `"6844002878440030"`):
  * Cifrado Original: `201919f99f96202aef26cdff9eb3374d`
  * Cifrado Alterado:  `e549e06690d10f1d7132417a5b7e0629`
* **Diferença de bits**: **64 de 128 bits** divergentes
* **Porcentagem**: $$\frac{64}{128} \times 100\% = \mathbf{50{,}00\%}$$

*Conclusão*: O algoritmo implementado atinge o patamar ideal de dispersão de Shannon (**Confusão e Difusão** plenas).

---

## 7. Montagem do Quadro Serial Binário UART2

O Transmissor empacota os dados e transmite fisicamente via `Serial2.write` a 115200 bps através do pino **GPIO 17**.

Estrutura física do pacote (34 bytes binários brutos):
```text
Byte 0:  0xAA  (Marcador de sincronismo de início de quadro)
Byte 1:  0x02  (Quantidade de blocos AES transmitidos: n = 2)
Bytes 2 a 33:  (32 bytes da carga útil cifrada)
  20 19 19 F9 9F 96 20 2A EF 26 CD FF 9E B3 37 4D
  5C 7F A1 6D 88 CB 3C 29 F0 AE C6 B3 C2 04 D9 66
```

Essa sequência exata de 34 bytes elétricos é recebida pelo pino GPIO 16 do Receptor da Lorena, onde o processo inverso restaura com precisão matemática a mensagem original da dupla.

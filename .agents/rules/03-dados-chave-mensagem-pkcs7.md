# Regras de Derivação de Dados: Chave, Mensagem e PKCS#7

## 1. Composição da Chave Simétrica (16 Bytes / 128 Bits)
- Integrantes:
  - **Aluno A**: Mateus
  - **Aluno B**: Lorena
- **Regra de Derivação**:
  1. Extrair os **8 últimos dígitos** da matrícula do Aluno A. Se tiver menos de 8 dígitos, preencher com `'0'` à esquerda.
  2. Extrair os **8 últimos dígitos** da matrícula do Aluno B. Se tiver menos de 8 dígitos, preencher com `'0'` à esquerda.
  3. Converter cada caractere numérico para seu respectivo código ASCII de 1 byte (exemplo: `'0'` $\to$ `0x30`, `'2'` $\to$ `0x32`).
  4. Concatenar os 8 bytes de A seguidos dos 8 bytes de B, totalizando exatamente **16 bytes**.

---

## 2. Formatação da Mensagem e Preenchimento PKCS#7
- **Texto Claro Base**:
  ```text
  A:<matrícula completa A>;B:<matrícula completa B>
  ```
- **Preenchimento PKCS#7 (RFC 5652)**:
  - O AES exige blocos estritamente múltiplos de 16 bytes.
  - Calculam-se os bytes faltantes $p$:
    - Se $L \pmod{16} \neq 0$: $p = 16 - (L \pmod{16})$.
    - Se $L \pmod{16} == 0$: $p = 16$ (adiciona-se um bloco completo de 16 bytes de valor `0x10`).
  - Acrescentam-se $p$ bytes, onde **cada byte adicionado possui valor igual a $p$**.
  - No receptor: após a decifragem, inspeciona-se o último byte $p$ ($1 \le p \le 16$). Se todos os últimos $p$ bytes forem iguais a $p$, remove-se o preenchimento para recuperar a string original.

---

## 3. Modo de Operação ECB (Electronic Codebook)
- Cada bloco de 16 bytes é cifrado de maneira totalmente independente usando a mesma chave $K$:
  $$C_i = E_K(P_i)$$
- **Objetivo Didático**: Isolar a cifra de bloco sem a complexidade adicional de vetores de inicialização (IV).
- **Insegurança Crítica do ECB (Exigência Teórica)**:
  - Blocos idênticos de texto claro produzem blocos idênticos de texto cifrado ($P_i = P_j \implies C_i = C_j$).
  - Não oculta padrões de dados (ex: imagens e comandos repetidos).
  - Vulnerável a ataques de repetição (*replay attack*), inserção, deleção e reordenação de blocos sem conhecimento da chave.
  - Alternativas seguras exigidas no relatório: CBC, CTR (com IV aleatório por mensagem) e modos autenticados como GCM (Galois/Counter Mode).

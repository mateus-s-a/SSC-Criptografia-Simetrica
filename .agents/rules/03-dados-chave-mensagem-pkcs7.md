# Regras de Derivação de Dados: Chave, Mensagem e PKCS#7

## 1. Composição da Chave Simétrica (16 Bytes / 128 Bits)
- Integrantes e Matrículas:
  - **Aluno A**: Lorena — `2023278440028` (8 últimos dígitos: `78440028`)
  - **Aluno B**: Mateus — `2023278440030` (8 últimos dígitos: `78440030`)
- **Regra de Derivação da Chave da Dupla**:
  1. 8 últimos dígitos de A (Lorena): `78440028`
  2. 8 últimos dígitos de B (Mateus): `78440030`
  3. Chave Concatenada em ASCII: `7844002878440030`
  4. Chave em Hexadecimal: `37383434303032383738343430303330`

---

## 2. Formatação da Mensagem e Preenchimento PKCS#7
- **Texto Claro da Dupla**:
  ```text
  A:2023278440028;B:2023278440030
  ```
  *(Tamanho total: 31 bytes)*
- **Preenchimento PKCS#7 da Dupla**:
  - Como faltava exatamente 1 byte para completar 32 bytes (2 blocos de 16), acrescenta-se $p = 1$ byte com valor `0x01`.
  - **Mensagem com PKCS#7 (Hex)**:
    `413a323032333237383434303032383b423a3230323332373834343030333001`
  - Bloco 1 (16 bytes): `413a323032333237383434303032383b` (`A:2023278440028;`)
  - Bloco 2 (16 bytes): `423a3230323332373834343030333001` (`B:2023278440030\x01`)
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

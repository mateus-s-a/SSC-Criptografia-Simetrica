# Relatório Técnico (Até 4 páginas)

- **Disciplina**: Segurança de Sistemas de Computação — Criptografia Simétrica
- **Dupla e Matrículas**:
  - **Aluno A**: Lorena — `2023278440028` (Receptor RX)
  - **Aluno B**: Mateus — `2023278440030` (Transmissor TX)
- **Status Atual**: A dupla está definindo em conjunto como e em qual formato (ex: Markdown, LaTeX ou Word/Docs) irão elaborar o relatório.

## Dados da Etapa 3 Gerados para a Dupla:
- **Chave (ASCII)**: `7844002878440030`
- **Chave (Hex)**: `37383434303032383738343430303330`
- **Mensagem Clara (31 bytes)**: `A:2023278440028;B:2023278440030`
- **Mensagem com PKCS#7 (Hex - 32 bytes)**: `413a323032333237383434303032383b423a3230323332373834343030333001`
  - Bloco 1 (Hex): `413a323032333237383434303032383b`
  - Bloco 2 (Hex): `423a3230323332373834343030333001`
- **Texto Cifrado Final (ECB)**:
  - Bloco 1 Cifrado: `201919f99f96202aef26cdff9eb3374d`
  - Bloco 2 Cifrado: `5c7fa16d88cb3c29f0aec6b3c204d966`
- **Chaves de Rodada da Expansão**:
  - Chave de Rodada 0: `37383434303032383738343430303330`
  - Chave de Rodada 1: `32fb303002cb020835f3363c05c3050c`
- **Cinco Estados do Bloco 1 (Rodada 1)**:
  - (1) Após AddRoundKey Inicial: `760206040203000f0f0c000400020b0b`
  - (2) Após SubBytes: `38776ff2777b637676fe63f263772b2b`
  - (3) Após ShiftRows: `387b632b77fe2bf276776f76637763f2`
  - (4) Após MixColumns: `b540f8062e1fd2b36c5f456ecedadf4e`
  - (5) Após AddRoundKey (Chave 1): `87bbc8362cd4d0bb59ac7352cb19da42`
- **Efeito Avalanche (Bloco 1)**:
  - Inversão de 1 bit na Mensagem: 63/128 bits divergentes (49.22%)
  - Inversão de 1 bit na Chave: 64/128 bits divergentes (50.00%)

## Seções Exigidas pelo Professor:
1. Registros em hexadecimal (chave, mensagem com PKCS#7, texto cifrado final e chaves de rodada 0 e 1).
2. Cinco estados intermediários do Bloco 1 na Rodada 1.
3. Teste do Efeito Avalanche (inversão de 1 bit e contagem de bits divergentes no cifrado).
4. Discussão crítica sobre o modo ECB (por que não usar, o que o espião aprende na UART com a repetição de comandos e alternativas como CBC, CTR e GCM).

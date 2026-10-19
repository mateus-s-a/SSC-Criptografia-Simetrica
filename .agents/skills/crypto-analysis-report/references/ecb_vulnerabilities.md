# Vulnerabilidades do Modo ECB (Electronic Codebook)

## 1. Por que o Modo ECB Não é Recomendado na Prática?
O modo ECB (*Electronic Codebook*) é a forma mais elementar de operar uma cifra de bloco. Nele, o texto claro é dividido em blocos de 128 bits (16 bytes) e cada bloco $P_i$ é transformado no bloco cifrado $C_i$ usando a mesma chave $K$:
$$C_i = E_K(P_i)$$

Apesar de computacionalmente simples e paralelizado, **o modo ECB é terminantemente desaconselhado para segurança real** devido a falhas intrínsecas:

### A. Preservação de Padrões e Determinismo
- Se dois blocos de entrada forem rigorosamente iguais ($P_i = P_j$), os blocos de saída serão idênticos ($C_i = C_j$).
- **Caso dos Comandos no Enunciado**:
  - Bloco 1: `"LIGAR LED VERDE."` $\to$ `e0c22a6f02664f487dc9528642203dec`
  - Bloco 2: `"DESLIGAR LED    "` $\to$ `2b4d065ea65478b60696616244cd5070`
  - Bloco 3: `"LIGAR LED VERDE."` $\to$ `e0c22a6f02664f487dc9528642203dec`
- **O que um espião na UART aprende com isso?**
  1. O invasor identifica a repetição de padrões mesmo sem conhecer a chave simétrica.
  2. Ele descobre a frequência e o ritmo com que determinadas ações ocorrem (análise de tráfego).
  3. Pode correlacionar eventos físicos com blocos cifrados (por exemplo, ao ver o LED verde acender, associa aquele criptograma específico à ação de ligar).

### B. Ataques Ativos de Replay, Reordenação e Substituição
- Como os blocos são isolados e não possuem encadeamento ou autenticação:
  - **Ataque de Replay (Reenvio)**: O atacante grava o bloco correspondente a "LIGAR LED VERDE." e o injeta na UART posteriormente quando quiser acender o LED, sem precisar decifrar.
  - **Substituição de Blocos**: O invasor pode trocar a ordem dos blocos ou substituir um bloco cifrado legítimo por outro bloco previamente capturado.
  - O receptor não tem nenhum mecanismo criptográfico para detectar que os blocos foram trocados ou repetidos.

---

## 2. Que Modos Devem Ser Usados na Prática?

| Modo | Características | Por que resolve o problema do ECB? |
| :--- | :--- | :--- |
| **CBC (Cipher Block Chaining)** | Cada bloco de texto claro passa por um XOR com o bloco cifrado anterior antes de ser cifrado. O primeiro bloco usa um **Vetor de Inicialização (IV)** aleatório. | Mesmo que dois blocos de texto claro sejam idênticos, seus criptogramas serão totalmente distintos. Além disso, a troca de blocos destrói a decifragem subsequente. |
| **CTR (Counter Mode)** | Transforma a cifra de bloco em uma cifra de fluxo (*stream cipher*). Cifra-se uma combinação de *Nonce* + Contador incremental e faz-se XOR com a mensagem. | Não há repetição de blocos, permite acesso aleatório e alta paralelização. Exige garantir que o par (*Nonce*, Contador) nunca seja reutilizado com a mesma chave. |
| **GCM (Galois/Counter Mode)** | Modo moderno autenticado (AEAD). Combina o modo CTR para confidencialidade com autenticação via teoria de Galois ($GHASH$) para gerar uma *Tag* de autenticação. | **Padrão ouro atual**: Garante tanto a confidencialidade quanto a **integridade** e autenticidade da mensagem. Qualquer tentativa de adulteração, injeção ou reordenação de bytes na UART é rejeitada de imediato antes da decifragem. |

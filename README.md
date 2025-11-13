# IDEA em Java — Criptografia Aplicada (PUC Goiás)

> Implementação didática do **IDEA (International Data Encryption Algorithm)** em **Java 17**, pronta para importar no IntelliJ IDEA (projeto **Maven**).  
> Foco: código limpo, legibilidade e fidelidade ao algoritmo original (bloco **64 bits**, chave **128 bits**).

## 📌 Destaques
- Núcleo do **IDEA** (8 rodadas + transformação final).
- Operações: `XOR`, **soma mod 2¹⁶**, **multiplicação mod (2¹⁶+1)** com convenção `0 ↔ 65536`.
- **Expansão de chave** (52 subchaves de 16 bits) por **rotações de 25 bits**.
- **ECB** e **CBC** com **PKCS#7**.
- **CLI** (`IdeaDemo`) para testes rápidos.
- **JUnit 5** com testes de ida-e-volta (encrypt → decrypt = original).
- Projeto enxuto e organizado (Clean Code).


---

## 🧠 Visão rápida do IDEA
O IDEA cifra blocos de **64 bits** usando chave de **128 bits**. Cada uma das **8 rodadas** aplica combinações de:
- **Multiplicação mod 65.537** (com a convenção de que `0` representa `65.536`),
- **Soma mod 2¹⁶**,
- `XOR`,
seguida por uma **transformação final**.  
A **expansão de chave** gera **52 subchaves** de 16 bits por rotações sucessivas de 25 bits sobre o estado de 128 bits da chave.

---

## 🗂️ Estrutura do projeto
```
idea-java/
├─ pom.xml
├─ README.md
├─ src/main/java/com/igor/crypto/idea/
│  ├─ IdeaCipher.java      # Núcleo: bloco, subchaves, rodadas, ECB/CBC
│  ├─ IdeaDemo.java        # CLI para cifrar/decifrar
│  ├─ Hex.java             # Utilitário Hex ↔ bytes
│  ├─ ByteOps.java         # Leitura/escrita big-endian de 16 bits
│  └─ Padding.java         # PKCS#7
└─ src/test/java/com/igor/crypto/idea/
   └─ IdeaCipherTest.java  # Testes JUnit (ECB/CBC round-trip)
```

---

## 🚀 Como executar (IntelliJ + Maven)
**Pré-requisitos:** Java 17 e Maven.

```bash
# dentro da pasta idea-java
mvn -q test            # roda os testes JUnit
mvn -q -DskipTests package

# CLI (ECB)
java -cp target/idea-java-1.0.0.jar com.igor.crypto.idea.IdeaDemo ecb enc   00112233445566778899AABBCCDDEEFF   --plaintext "Mensagem secreta!"

# CLI (CBC)
java -cp target/idea-java-1.0.0.jar com.igor.crypto.idea.IdeaDemo cbc enc   00112233445566778899AABBCCDDEEFF   --iv 0001020304050607   --hex 4E657465206D656E736167656D
```

**Parâmetros do CLI**
- **Modo**: `ecb` | `cbc`
- **Operação**: `enc` (cifrar) | `dec` (decifrar)
- **Chave (HEX)**: 32 hex (128 bits)
- **IV (HEX)**: 16 hex (64 bits) — obrigatório no CBC
- **Entrada**: `--plaintext "..."` (UTF‑8) ou `--hex <BYTES_HEX>`

> **Dica:** Para checar rapidamente, rode os testes (`mvn test`).

---

## 💻 Uso por código (API)
```java
import com.igor.crypto.idea.IdeaCipher;
import com.igor.crypto.idea.Hex;

byte[] key = Hex.fromHex("00112233445566778899AABBCCDDEEFF");
byte[] iv  = Hex.fromHex("0001020304050607");

IdeaCipher idea = new IdeaCipher(key);

// ECB
byte[] ctEcb = idea.encryptEcb("texto".getBytes());
byte[] ptEcb = idea.decryptEcb(ctEcb);

// CBC
byte[] ctCbc = idea.encryptCbc("texto".getBytes(), iv);
byte[] ptCbc = idea.decryptCbc(ctCbc, iv);
```

---

## 🧩 Detalhes de implementação
- **Subchaves (52 × 16 bits):** derivadas da chave de 128 bits por **rotações de 25 bits** entre blocos de 8 palavras (16 bits).  
- **Operações de grupo:**
  - `add(a,b) = (a + b) mod 2^16`
  - `mul(a,b) = (a ⨉ b) mod 65.537` com `0 ↔ 65.536`
  - `inv(x)` = inverso multiplicativo mod 65.537 (Euclides estendido)
- **Decriptação:** usa **subchaves invertidas** (inversos/negativos) conforme a especificação.
- **Modos:**
  - **ECB:** bloco a bloco, com `PKCS#7`.
  - **CBC:** `Pᵢ ⊕ Cᵢ₋₁` antes de cifrar; `IV` de 8 bytes.

---

## 🔐 Notas de segurança (importante)
- **IDEA** é clássico e robusto, mas tem **bloco de 64 bits** — isso limita o volume seguro por chave (risco de colisões por **aniversário**).  
- Evite **ECB** para dados reais (vazamento de padrões). Prefira **CBC** com IV aleatório **único por mensagem**.  
- Para produção, considere modos **autenticados** (ex.: AES‑GCM/ChaCha20‑Poly1305).  
- Este projeto é **educacional**; não há hardening/side‑channel protection.

---

## 🧪 Testes
- `IdeaCipherTest` cobre:
  - **ECB round-trip**
  - **CBC round-trip**
  - Validações de tamanho de chave/IV
- Execute: `mvn test`

---

## ❓ FAQ
**Posso usar outra versão do Java?**  
O projeto foi configurado para **Java 17**. Versões superiores devem funcionar ajustando o `pom.xml` se necessário.

**Quero CFB/OFB.**  
A estrutura permite adicionar facilmente (posso incluir sob demanda).

**Como gerar/ler HEX?**  
Use `Hex.toHex(byte[])` e `Hex.fromHex(String)`.

---

## 📚 Referências introdutórias
- International Data Encryption Algorithm (IDEA), X. Lai e J. Massey.
- Materiais de aula de Criptografia Aplicada (PUC Goiás).

---

## 📄 Licença
Uso **educacional**. Adapte livremente com créditos.

— *Igor Ferreira*

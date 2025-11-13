# IDEA (International Data Encryption Algorithm) – Implementação em Java

Projeto **Maven** pronto para importar no IntelliJ. Inclui:
- `IdeaCipher` (bloco de 64 bits, chave de 128 bits)
- Modos **ECB** e **CBC** com **PKCS#7**
- Utilitários (`Hex`, `ByteOps`)
- `IdeaDemo` (CLI)
- Testes básicos de sanidade (cripta/decripta = original)

## Como usar (CLI)
```bash
mvn -q -DskipTests package
java -cp target/idea-java-1.0.0.jar com.igor.crypto.idea.IdeaDemo ecb enc \
  00112233445566778899AABBCCDDEEFF \  --plaintext "Mensagem secreta!"
# CBC
java -cp target/idea-java-1.0.0.jar com.igor.crypto.idea.IdeaDemo cbc enc \  00112233445566778899AABBCCDDEEFF --iv 0001020304050607 \  --hex "4E65746520656D20756D206C7567617221"
```

### Parâmetros
- **Modo**: `ecb` | `cbc`
- **Operação**: `enc` (cifrar) | `dec` (decifrar)
- **Chave** (hex, 32 hex chars = 128 bits)
- **`--iv`** (hex, 16 hex chars = 64 bits, apenas CBC)
- **Entrada**: `--plaintext "..."` (texto) ou `--hex <HEX>` (bytes em hex)

Saída: imprime em **hex**. Para `dec`, imprime o texto (UTF-8) e o hex.

> Observação: A implementação segue a especificação clássica do IDEA (8 rodadas + transformação final), com as operações: XOR, soma mod 2¹⁶ e multiplicação mod (2¹⁶+1) com a convenção 0↔65536.

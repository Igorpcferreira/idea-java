package com.igor.crypto.idea;

import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import static org.junit.jupiter.api.Assertions.*;

public class IdeaCipherTest {

    @Test
    public void encryptDecryptEcb_Roundtrip() {
        byte[] key = Hex.fromHex("00112233445566778899AABBCCDDEEFF");
        IdeaCipher idea = new IdeaCipher(key);
        String msg = "Teste IDEA ECB - roundtrip ✅";
        byte[] ct = idea.encryptEcb(msg.getBytes(StandardCharsets.UTF_8));
        byte[] pt = idea.decryptEcb(ct);
        assertEquals(msg, new String(pt, StandardCharsets.UTF_8));
    }

    @Test
    public void encryptDecryptCbc_Roundtrip() {
        byte[] key = Hex.fromHex("00112233445566778899AABBCCDDEEFF");
        byte[] iv  = Hex.fromHex("0001020304050607");
        IdeaCipher idea = new IdeaCipher(key);
        String msg = "Teste IDEA CBC - roundtrip ✅";
        byte[] ct = idea.encryptCbc(msg.getBytes(StandardCharsets.UTF_8), iv);
        byte[] pt = idea.decryptCbc(ct, iv);
        assertEquals(msg, new String(pt, StandardCharsets.UTF_8));
    }

    @Test
    public void invalidKeySize() {
        assertThrows(IllegalArgumentException.class, () -> new IdeaCipher(new byte[15]));
    }

    @Test
    public void invalidIvSize() {
        byte[] key = Hex.fromHex("00112233445566778899AABBCCDDEEFF");
        IdeaCipher idea = new IdeaCipher(key);
        assertThrows(IllegalArgumentException.class, () -> idea.encryptCbc("a".getBytes(StandardCharsets.UTF_8), new byte[7]));
    }
}

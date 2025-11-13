package com.igor.crypto.idea;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class IdeaDemo {
    public static void main(String[] args) {
        if (args.length < 4) {
            System.out.println("Uso:");
            System.out.println("  java ... IdeaDemo <ecb|cbc> <enc|dec> <KEY_HEX_32> (--iv IV_HEX_16)? (--plaintext TXT | --hex HEXDATA)");
            System.out.println("Ex1: ecb enc 00112233445566778899AABBCCDDEEFF --plaintext \"Mensagem secreta!\"");
            System.out.println("Ex2: cbc enc 00112233445566778899AABBCCDDEEFF --iv 0001020304050607 --hex 4E657465");
            System.exit(1);
        }
        String mode = args[0].toLowerCase();
        String op = args[1].toLowerCase();
        byte[] key = Hex.fromHex(args[2]);
        if (key.length != 16) {
            throw new IllegalArgumentException("A chave deve ter 128 bits (32 hex).");
        }

        byte[] iv = null;
        byte[] input = null;
        boolean isText = false;

        for (int i = 3; i < args.length; i++) {
            switch (args[i]) {
                case "--iv" -> {
                    iv = Hex.fromHex(args[++i]);
                    if (iv.length != 8) throw new IllegalArgumentException("IV deve ter 8 bytes (16 hex).");
                }
                case "--plaintext" -> {
                    isText = true;
                    input = args[++i].getBytes(StandardCharsets.UTF_8);
                }
                case "--hex" -> input = Hex.fromHex(args[++i]);
                default -> { /* ignore */ }
            }
        }
        if (input == null) throw new IllegalArgumentException("Forneça --plaintext ou --hex.");

        IdeaCipher idea = new IdeaCipher(key);
        if ("enc".equals(op)) {
            byte[] out = switch (mode) {
                case "ecb" -> idea.encryptEcb(input);
                case "cbc" -> {
                    if (iv == null) throw new IllegalArgumentException("CBC requer --iv.");
                    yield idea.encryptCbc(input, iv);
                }
                default -> throw new IllegalArgumentException("Modo inválido: " + mode);
            };
            System.out.println(Hex.toHex(out));
        } else if ("dec".equals(op)) {
            byte[] out = switch (mode) {
                case "ecb" -> idea.decryptEcb(input);
                case "cbc" -> {
                    if (iv == null) throw new IllegalArgumentException("CBC requer --iv.");
                    yield idea.decryptCbc(input, iv);
                }
                default -> throw new IllegalArgumentException("Modo inválido: " + mode);
            };
            System.out.println("Texto: " + new String(out, StandardCharsets.UTF_8));
            System.out.println("HEX  : " + Hex.toHex(out));
        } else {
            throw new IllegalArgumentException("Operação inválida: " + op);
        }
    }
}

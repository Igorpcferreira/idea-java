package com.igor.crypto.idea;

import java.util.Arrays;

/**
 * Implementação do IDEA (International Data Encryption Algorithm).
 * Bloco: 64 bits, Chave: 128 bits.
 *
 * Operações de cada rodada seguem a especificação (8 rodadas + transformação final).
 */
public final class IdeaCipher {
    public static final int BLOCK_SIZE = 8; // 64 bits
    private static final int ROUNDS = 8;
    private static final int MOD_ADD_MASK = 0xFFFF;
    private static final int MOD_MUL = 0x10001; // 65537

    private final int[] encSub; // 52 subchaves de 16 bits (armazenadas como int 0..65535)
    private final int[] decSub;

    public IdeaCipher(byte[] key128) {
        if (key128 == null || key128.length != 16) {
            throw new IllegalArgumentException("Chave deve ter 128 bits (16 bytes).");
        }
        this.encSub = generateEncryptionSubkeys(key128);
        this.decSub = generateDecryptionSubkeys(encSub);
    }

    public byte[] encryptBlock(byte[] block8) {
        if (block8.length != BLOCK_SIZE) throw new IllegalArgumentException("Bloco deve ter 8 bytes.");
        int x1 = ByteOps.be16(block8, 0);
        int x2 = ByteOps.be16(block8, 2);
        int x3 = ByteOps.be16(block8, 4);
        int x4 = ByteOps.be16(block8, 6);

        int p = 0; // índice nas subchaves
        for (int round = 0; round < ROUNDS; round++) {
            int k1 = encSub[p++];
            int k2 = encSub[p++];
            int k3 = encSub[p++];
            int k4 = encSub[p++];
            int k5 = encSub[p++];
            int k6 = encSub[p++];

            x1 = mul(x1, k1);
            x2 = add(x2, k2);
            x3 = add(x3, k3);
            x4 = mul(x4, k4);

            int t0 = x1 ^ x3;
            int t1 = x2 ^ x4;

            t0 = mul(t0, k5);
            t1 = add(t1, t0);
            t1 = mul(t1, k6);
            t0 = add(t0, t1);

            x1 ^= t1;
            x4 ^= t0;

            int x2old = x2;
            x2 = x3 ^ t0;
            x3 = x2old ^ t1;
        }

        int k1 = encSub[p++];
        int k2 = encSub[p++];
        int k3 = encSub[p++];
        int k4 = encSub[p];

        int y1 = mul(x1, k1);
        int y2 = add(x3, k2);
        int y3 = add(x2, k3);
        int y4 = mul(x4, k4);

        byte[] out = new byte[BLOCK_SIZE];
        ByteOps.putBe16(y1, out, 0);
        ByteOps.putBe16(y2, out, 2);
        ByteOps.putBe16(y3, out, 4);
        ByteOps.putBe16(y4, out, 6);
        return out;
    }

    public byte[] decryptBlock(byte[] block8) {
        if (block8.length != BLOCK_SIZE) throw new IllegalArgumentException("Bloco deve ter 8 bytes.");
        int x1 = ByteOps.be16(block8, 0);
        int x2 = ByteOps.be16(block8, 2);
        int x3 = ByteOps.be16(block8, 4);
        int x4 = ByteOps.be16(block8, 6);

        int p = 0;
        for (int round = 0; round < ROUNDS; round++) {
            int k1 = decSub[p++];
            int k2 = decSub[p++];
            int k3 = decSub[p++];
            int k4 = decSub[p++];
            int k5 = decSub[p++];
            int k6 = decSub[p++];

            x1 = mul(x1, k1);
            x2 = add(x2, k2);
            x3 = add(x3, k3);
            x4 = mul(x4, k4);

            int t0 = x1 ^ x3;
            int t1 = x2 ^ x4;

            t0 = mul(t0, k5);
            t1 = add(t1, t0);
            t1 = mul(t1, k6);
            t0 = add(t0, t1);

            x1 ^= t1;
            x4 ^= t0;

            int x2old = x2;
            x2 = x3 ^ t0;
            x3 = x2old ^ t1;
        }

        int k1 = decSub[p++];
        int k2 = decSub[p++];
        int k3 = decSub[p++];
        int k4 = decSub[p];

        int y1 = mul(x1, k1);
        int y2 = add(x3, k2);
        int y3 = add(x2, k3);
        int y4 = mul(x4, k4);

        byte[] out = new byte[BLOCK_SIZE];
        ByteOps.putBe16(y1, out, 0);
        ByteOps.putBe16(y2, out, 2);
        ByteOps.putBe16(y3, out, 4);
        ByteOps.putBe16(y4, out, 6);
        return out;
    }

    // ======== Subchaves ========
    private static int[] generateEncryptionSubkeys(byte[] key) {
        int[] sub = new int[52];
        // Representa a chave como 8 palavras de 16 bits (big-endian)
        int[] words = new int[8];
        for (int i = 0; i < 8; i++) {
            words[i] = ((key[2*i] & 0xFF) << 8) | (key[2*i+1] & 0xFF);
        }

        int generated = 0;
        int idx = 0;
        while (generated < 52) {
            // gerar até 8 subchaves da janela atual
            for (int i = 0; i < 8 && generated < 52; i++) {
                sub[generated++] = words[i] & 0xFFFF;
            }
            // rotaciona 128 bits à esquerda em 25 bits para próxima janela
            words = rotateLeft25(words);
            idx++;
        }
        return sub;
    }

    private static int[] rotateLeft25(int[] words) {
        // Rotação de 25 bits = rotação de 16 bits (troca de palavras por 1) + rotação de 9 bits cruzada
        int[] w16 = new int[8];
        for (int i = 0; i < 8; i++) w16[i] = words[(i + 1) & 7]; // rotate by one word (16 bits)

        int[] out = new int[8];
        for (int i = 0; i < 8; i++) {
            // leva 9 bits da palavra atual + 7 bits da palavra anterior
            int cur = w16[i];
            int prev = w16[(i + 7) & 7];
            out[i] = ((cur << 9) & 0xFFFF) | (prev >>> 7);
        }
        return out;
    }

    private static int[] generateDecryptionSubkeys(int[] enc) {
        int[] dec = new int[52];
        int pEnc = 0;
        int pDec = 52;

        // Final transform (enc subchaves 49..52) -> primeiras de dec (na ordem correta no final do loop)
        int z49 = enc[48], z50 = enc[49], z51 = enc[50], z52 = enc[51];

        // Preenche por rodadas inversas
        // i=8..1 (rodadas de cifragem) viram i=1..8 (rodadas de decifragem)
        int jEnc = 48; // aponta para início do último bloco de 6 subchaves (round 8)
        int jDec = 0;  // início das subchaves de dec

        for (int round = 0; round < ROUNDS; round++) {
            int baseEnc = 48 - 6*round; // 48,42,...,6
            int k1 = enc[baseEnc + 0];
            int k2 = enc[baseEnc + 1];
            int k3 = enc[baseEnc + 2];
            int k4 = enc[baseEnc + 3];
            int k5 = enc[baseEnc + 4];
            int k6 = enc[baseEnc + 5];

            dec[jDec + 0] = inv(k1);
            dec[jDec + 1] = neg(k2);
            dec[jDec + 2] = neg(k3);
            dec[jDec + 3] = inv(k4);

            // Para a primeira rodada de dec (que corresponde à última de enc), a ordem de k5/k6 é k5,k6
            // Para as demais, é invertida (k6,k5)
            if (round == 0) {
                dec[jDec + 4] = k5;
                dec[jDec + 5] = k6;
            } else {
                dec[jDec + 4] = k6;
                dec[jDec + 5] = k5;
            }
            jDec += 6;
        }

        // Subchaves finais de decifragem (usadas após as 8 rodadas)
        dec[48] = inv(z49);
        dec[49] = neg(z50);
        dec[50] = neg(z51);
        dec[51] = inv(z52);

        return dec;
    }

    // ======== Operações de grupo ========
    private static int add(int a, int b) {
        return (a + b) & MOD_ADD_MASK; // mod 2^16
    }

    private static int neg(int a) {
        return (0x10000 - (a & MOD_ADD_MASK)) & MOD_ADD_MASK; // -a mod 2^16
    }

    private static int mul(int a, int b) {
        if (a == 0) a = 0x10000;
        if (b == 0) b = 0x10000;
        long p = (long) a * (long) b;
        int r = (int) (p % MOD_MUL);
        if (r == 0x10000) r = 0; // 65536 -> 0
        return r & MOD_ADD_MASK;
    }

    private static int inv(int x) {
        if (x == 0) return 0; // por convenção no IDEA
        // inverso multiplicativo de x mod 65537 via Euclides estendido
        int t0 = 1, t1 = 0;
        int r0 = x, r1 = MOD_MUL;
        while (r0 != 1) {
            int q = r1 / r0;
            int r2 = r1 - q * r0;
            int t2 = t1 - q * t0;
            r1 = r0; r0 = r2;
            t1 = t0; t0 = t2;
            if (r0 == 0) break; // segurança
        }
        int inv = t0;
        inv %= MOD_MUL;
        if (inv < 0) inv += MOD_MUL;
        return inv & MOD_ADD_MASK;
    }

    // ======== Modos de operação ========
    public byte[] encryptEcb(byte[] data) {
        byte[] padded = Padding.pkcs7Pad(data, BLOCK_SIZE);
        byte[] out = new byte[padded.length];
        for (int i = 0; i < padded.length; i += BLOCK_SIZE) {
            byte[] c = encryptBlock(Arrays.copyOfRange(padded, i, i + BLOCK_SIZE));
            System.arraycopy(c, 0, out, i, BLOCK_SIZE);
        }
        return out;
    }

    public byte[] decryptEcb(byte[] data) {
        if ((data.length % BLOCK_SIZE) != 0) throw new IllegalArgumentException("Tamanho inválido para ECB");
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i += BLOCK_SIZE) {
            byte[] p = decryptBlock(Arrays.copyOfRange(data, i, i + BLOCK_SIZE));
            System.arraycopy(p, 0, out, i, BLOCK_SIZE);
        }
        return Padding.pkcs7Unpad(out, BLOCK_SIZE);
    }

    public byte[] encryptCbc(byte[] data, byte[] iv) {
        if (iv == null || iv.length != BLOCK_SIZE) throw new IllegalArgumentException("IV de 8 bytes requerido para CBC.");
        byte[] padded = Padding.pkcs7Pad(data, BLOCK_SIZE);
        byte[] out = new byte[padded.length];
        byte[] prev = Arrays.copyOf(iv, BLOCK_SIZE);
        for (int i = 0; i < padded.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(padded, i, i + BLOCK_SIZE);
            for (int j = 0; j < BLOCK_SIZE; j++) block[j] ^= prev[j];
            byte[] c = encryptBlock(block);
            System.arraycopy(c, 0, out, i, BLOCK_SIZE);
            prev = c;
        }
        return out;
    }

    public byte[] decryptCbc(byte[] data, byte[] iv) {
        if (iv == null || iv.length != BLOCK_SIZE) throw new IllegalArgumentException("IV de 8 bytes requerido para CBC.");
        if ((data.length % BLOCK_SIZE) != 0) throw new IllegalArgumentException("Tamanho inválido para CBC");
        byte[] out = new byte[data.length];
        byte[] prev = Arrays.copyOf(iv, BLOCK_SIZE);
        for (int i = 0; i < data.length; i += BLOCK_SIZE) {
            byte[] cur = Arrays.copyOfRange(data, i, i + BLOCK_SIZE);
            byte[] p = decryptBlock(cur);
            for (int j = 0; j < BLOCK_SIZE; j++) p[j] ^= prev[j];
            System.arraycopy(p, 0, out, i, BLOCK_SIZE);
            prev = cur;
        }
        return Padding.pkcs7Unpad(out, BLOCK_SIZE);
    }
}

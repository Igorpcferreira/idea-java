package com.igor.crypto.idea;

final class ByteOps {
    private ByteOps(){}

    static int be16(byte[] b, int off) {
        return ((b[off] & 0xFF) << 8) | (b[off + 1] & 0xFF);
    }
    static void putBe16(int v, byte[] b, int off) {
        b[off]     = (byte) ((v >>> 8) & 0xFF);
        b[off + 1] = (byte) (v & 0xFF);
    }
    static byte[] slice(byte[] a, int start, int len){
        byte[] s = new byte[len];
        System.arraycopy(a, start, s, 0, len);
        return s;
    }
}

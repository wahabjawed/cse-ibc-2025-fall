package org.example;

import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

// Press Shift twice to open the Search Everywhere dialog and type `show whitespaces`,
// then press Enter. You can now see whitespace characters in your code.
public class Main {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {

        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        String bcPub = compressPubKey(pubKey);
        MessageDigest sha = MessageDigest.getInstance("SHA-256");

        byte[] s1 = sha.digest(hexStringToByteArray(bcPub));

        String sha_hash = bytesToHex(s1);
        System.out.println(sha_hash);

        RIPEMD160Digest ripemd = new RIPEMD160Digest();
        byte[] r1 = new byte[ripemd.getDigestSize()];
        ripemd.update(s1,0,s1.length);
        ripemd.doFinal(r1,0);


        String ripemd_hash = bytesToHex(r1);
        System.out.println(ripemd_hash);



    }
    public static String compressPubKey(BigInteger pubKey) {

        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";

        String pubKeyHex = pubKey.toString(16);

        String pubKeyX = pubKeyHex.substring(0, 64);

        return pubKeyYPrefix + pubKeyX;

    }
    public static byte[] hexStringToByteArray(String s) {

        byte[] b = new byte[s.length() / 2];

        for (int i = 0; i < b.length; i++) {

            int index = i * 2;

            int v = Integer.parseInt(s.substring(index, index + 2), 16);

            b[i] = (byte) v;

        }

        return b;

    }
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
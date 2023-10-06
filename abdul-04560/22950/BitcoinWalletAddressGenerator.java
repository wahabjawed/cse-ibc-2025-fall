/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.bc;


import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class BitcoinWalletAddressGenerator {

    public static void main(String[] args) throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException {

        // Generate a new Ethereum-compatible EC key pair
        BigInteger privateKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger publicKey = Sign.publicKeyFromPrivate(privateKey);

        // Compress the public key
        String compressedPublicKey = compressPublicKey(publicKey);

        // Calculate SHA-256 hash
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        byte[] sha256Hash = sha256Digest.digest(hexStringToByteArray(compressedPublicKey));
        String sha256HashHex = bytesToHexString(sha256Hash);
        System.out.println("SHA-256 Hash: " + sha256HashHex);

        // Calculate RIPEMD-160 hash
        RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
        byte[] ripemd160Hash = new byte[ripemd160Digest.getDigestSize()];
        ripemd160Digest.update(sha256Hash, 0, sha256Hash.length);
        ripemd160Digest.doFinal(ripemd160Hash, 0);
        String ripemd160HashHex = bytesToHexString(ripemd160Hash);
        System.out.println("RIPEMD-160 Hash: " + ripemd160HashHex);
    }

    public static String compressPublicKey(BigInteger publicKey) {
        String publicKeyPrefix = publicKey.testBit(0) ? "03" : "02";
        String publicKeyHex = publicKey.toString(16);
        String publicKeyX = publicKeyHex.substring(0, 64);
        return publicKeyPrefix + publicKeyX;
    }

    public static byte[] hexStringToByteArray(String hexString) {
        byte[] byteArray = new byte[hexString.length() / 2];
        for (int i = 0; i < byteArray.length; i++) {
            int index = i * 2;
            int value = Integer.parseInt(hexString.substring(index, index + 2), 16);
            byteArray[i] = (byte) value;
        }
        return byteArray;
    }

    public static String bytesToHexString(byte[] bytes) {
        StringBuilder hexStringBuilder = new StringBuilder();
        for (byte b : bytes) {
            hexStringBuilder.append(String.format("%02x", b));
        }
        return hexStringBuilder.toString();
    }
}

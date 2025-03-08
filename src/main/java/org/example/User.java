package org.example;

import java.security.*;

class User {
    public String walletAddress;
    public PrivateKey privateKey;
    public PublicKey publicKey;

    public User() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair pair = keyGen.generateKeyPair();
            this.privateKey = pair.getPrivate();
            this.publicKey = pair.getPublic();
            this.walletAddress = Blockchain.applySHA256(publicKey.toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] signTransaction(String data) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initSign(privateKey);
            rsa.update(data.getBytes());
            return rsa.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static boolean verifySignature(PublicKey publicKey, String data, byte[] signature) {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initVerify(publicKey);
            rsa.update(data.getBytes());
            return rsa.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
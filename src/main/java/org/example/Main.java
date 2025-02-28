package org.example;


import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter; // Ensure Bouncy Castle Provider library with openssl support is added to dependencies
import java.io.StringWriter;
import javax.crypto.Cipher;
public class Main {
    static {
        Security.addProvider(new BouncyCastleProvider()); // Add Bouncy Castle Provider
    }

    public static void main(String[] args) throws Exception {
        String name = "Abdur Rehman Nasir";

        // Generate RSA Key Pair (PEM Format)
        KeyPair rsaKeyPair = generateRSAKeyPair();
        System.out.println("Public Key (PEM):\n" + convertToPEM(rsaKeyPair.getPublic()));
        System.out.println("Private Key (PEM):\n" + convertToPEM(rsaKeyPair.getPrivate()));

        // Hashing with SHA-256, SHA3-256, and RIPEMD-160
        System.out.println("SHA-256 Hash: " + hashWithAlgorithm("SHA-256", name));
        System.out.println("SHA3-256 Hash: " + hashWithAlgorithm("SHA3-256", name));
        System.out.println("RIPEMD-160 Hash: " + ripemd160Hash(name));

        // Generate Bitcoin Wallet Address using ECC (secp256k1)
        String bitcoinAddress = generateBitcoinWalletECC();
        System.out.println("Bitcoin Wallet Address (ECC): " + bitcoinAddress);

        // Encrypt and Sign Name using RSA
        byte[] encryptedName = encryptRSA(name, rsaKeyPair.getPublic());
        System.out.println("Encrypted Name: " + Base64.getEncoder().encodeToString(encryptedName));

        byte[] signature = signData(name.getBytes(), rsaKeyPair.getPrivate());
        System.out.println("Digital Signature: " + Base64.getEncoder().encodeToString(signature));
    }

    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public static String convertToPEM(Key key) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(key);
        }
        return writer.toString();
    }

    public static String hashWithAlgorithm(String algorithm, String input) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = digest.digest(input.getBytes());
        return Hex.toHexString(hashBytes);
    }

    public static String ripemd160Hash(String input) {
        RIPEMD160Digest digest = new RIPEMD160Digest();
        byte[] inputBytes = input.getBytes();
        digest.update(inputBytes, 0, inputBytes.length);
        byte[] hashBytes = new byte[digest.getDigestSize()];
        digest.doFinal(hashBytes, 0);
        return Hex.toHexString(hashBytes);
    }

    public static String generateBitcoinWalletECC() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", "BC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256k1"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] sha256Hash = sha256.digest(keyPair.getPublic().getEncoded());

        RIPEMD160Digest ripemd160 = new RIPEMD160Digest();
        ripemd160.update(sha256Hash, 0, sha256Hash.length);
        byte[] ripemdHash = new byte[ripemd160.getDigestSize()];
        ripemd160.doFinal(ripemdHash, 0);

        return "1" + Hex.toHexString(ripemdHash).substring(0, 32);
    }

    public static byte[] encryptRSA(String data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }
}

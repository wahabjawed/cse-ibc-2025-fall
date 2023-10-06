import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;
import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import java.math.BigInteger;


public class Bitcoin {
    public static void main(String[] args) throws NoSuchAlgorithmException {

        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the message");
        String message = sc.nextLine();

        //Creating the MessageDigest object
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        //Passing data to the created MessageDigest Object
        md.update(message.getBytes());

        //Compute the message digest
        byte[] digest = md.digest();

        System.out.println(digest);

        //Converting the byte array in to HexString format
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }
        System.out.println("Hex format 256 : " + hexString.toString());
        //Creating the MessageDigest object
        MessageDigest md512 = MessageDigest.getInstance("SHA-512");

        //Passing data to the created MessageDigest Object
        md512.update(message.getBytes());

        //Compute the message digest
        byte[] digest512 = md512.digest();

        System.out.println(digest512);

        //Converting the byte array in to HexString format
        StringBuffer hexString512 = new StringBuffer();

        for (int i = 0; i < digest512.length; i++) {
            hexString512.append(Integer.toHexString(0xFF & digest512[i]));
        }
        System.out.println("Hex format 512 : " + hexString512.toString());

//        //Creating the MessageDigest object
//        MessageDigest rmd = MessageDigest.getInstance("RipeMD160");
//
//        //Passing data to the created MessageDigest Object
//        rmd.update(message.getBytes());
//
//        //Compute the message digest
//        byte[] digestrmd = rmd.digest();
//
//        System.out.println(digestrmd);
//
//        //Converting the byte array in to HexString format
//        StringBuffer rmdhexString = new StringBuffer();
//
//        for (int i = 0; i < digestrmd.length; i++) {
//            rmdhexString.append(Integer.toHexString(0xFF & digestrmd[i]));
//        }
//        System.out.println("Hex format RMD-160 : " + rmdhexString.toString());

        try {
            // Generate an RSA key pair with a key size of 2048 bits
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Get the public and private keys from the key pair
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // Convert the keys to Base64-encoded strings for easy storage or transmission
            String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
            String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());

            // Print the keys (you can also save them to files or use as needed)
            System.out.println("Public Key:");
            System.out.println(publicKeyBase64);

            System.out.println("\nPrivate Key:");
            System.out.println(privateKeyBase64);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String public_key = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCi5vm5Zz8IBjtdQ3lPn38Cgb7Xawxk451e0HBwlKW51yPnzjL1A6qqxHdX1PodQ8KmC6kpBjygLZ07AY3EBhF4CLuGVokMUAJYQ+/rHnUnpQWHhEfPuEouObFvSwaP8vpfw4sUXBhpA/1cDRi0bj0O/smyVV221RVBWC8NCoZhewIDAQAB";
        String private_key = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIkh7uDgiFNb06lr58kWKM0xjljK4JbOugmPsrpL5XELMKPIO0tZrOUScyfFlRW5EuMzWSaQIqEYepKoYhT9a8NElIGsPF43Hc248U2OGEl+axmzm7yz2vIRk6eBItv6VCP0wHm4um+6cWJvN/tVNKOeZYyu4Rw10tHDq/TTv1F/AgMBAAECgYA7MOprJn+xe3FhL7JcmbQC3eETcn5+mbyzY9NBloDyymG0UDlHzO1T8yLBiAdR2RDOANv6STypTGeb5hJv/PMGMRmQ6fTe/lGytL8dk5rnEs8RHM2HbsukuozptL4SyHKg1wLTEeB9JAN1Vu5Ydrkivo2Vq7uu281BmHaWDCyEAQJBAOS6UNU9D1NVmI6EtfBjUOdUrHdSLAfSEG71bhxbKWWUSAPcmvm/X3LVzrXdN8qEJcx6M4TIHSmhv8TV4dWspoMCQQCZe8Pry639++QFfBB/FAFxh586RcMYK3SxOkazMHZJaAdK65kOcRTfWVIJidQArxpGejlepX9qDg2ZjK0H5VhVAkABQ24y31V4Vl6zWtROcZ3+yR7ywcdwe56PnldvXKmL4BfNvag1fPMgBUJRCtnGCpjS2lHyh9BxbG1MvwmyTnPVAkAqNzqaXrmKxH/halB3Q59qBK2tL4cL3NgJ70eG/etrIWvwFYFR0ZS2IjFIYlqnnYISpIenGspC936SH3lwVIrJAkEApwLl8V1vc4qJRE2KTLZ+cq6EJSn77D5MQfSx2UBjek23+Oy+jTl+1CyPOG7hqbXCp+1IDYMkPF59OTVICbBO7A==";
        try {
            // Replace publicKeyBase64 with the actual Base64-encoded RSA public key
            String publicKeyBase64 = public_key;

            // Replace privateKeyBase64 with the actual Base64-encoded RSA private key
            String privateKeyBase64 = private_key;

            // Decode the Base64-encoded public and private keys
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyBase64);
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);

            // Create PublicKey and PrivateKey objects from the decoded bytes
            java.security.spec.X509EncodedKeySpec publicKeySpec = new java.security.spec.X509EncodedKeySpec(publicKeyBytes);
            java.security.spec.PKCS8EncodedKeySpec privateKeySpec = new java.security.spec.PKCS8EncodedKeySpec(privateKeyBytes);

            java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("RSA");
            java.security.PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            java.security.PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            // Initialize the Cipher for encryption using the public key
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Text to be encrypted
            String plaintext = message;
            byte[] encryptedBytes = encryptCipher.doFinal(plaintext.getBytes());

            // Encode the encrypted bytes to Base64 for transmission/storage
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);

            // Print or use the encrypted text
            System.out.println("Encrypted Text:");
            System.out.println(encryptedBase64);

        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            // Replace privateKeyBase64 with the actual Base64-encoded RSA private key
            String privateKeyBase64 = private_key;

            // Decode the Base64-encoded private key
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64);

            // Create a PrivateKey object from the decoded bytes
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            // Initialize a Signature object for signing using the private key
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);

            // Text to be signed
            String textToSign = message;

            // Update the Signature object with the data to be signed
            signature.update(textToSign.getBytes());

            // Generate the digital signature
            byte[] digitalSignature = signature.sign();

            // Encode the digital signature to Base64 for transmission/storage
            String signatureBase64 = Base64.getEncoder().encodeToString(digitalSignature);

            // Print or use the digital signature
            System.out.println("Digital Signature:");
            System.out.println(signatureBase64);

        } catch (Exception e) {
            e.printStackTrace();
        }
//


        //  Bitcoin
        // Step 1: Initialize the security service provider
        Security.addProvider(new BouncyCastleProvider());

        try {
            // Step 2: Generate ECDSA keypair
            ECKeyPair keyPair = generateECDSAKeypair();

            // Display the private and public keys
            System.out.println("Private key: " + keyPair.getPrivateKey().toString(16));
            System.out.println("Public key: " + keyPair.getPublicKey().toString(16));

            // Step 3: Generate hashes based on the public key
            String compressedPublicKey = compressPubKey(keyPair.getPublicKey());
            byte[] sha256Result = applySHA256(compressedPublicKey);
            byte[] ripemd160Result = applyRIPEMD160(sha256Result);

            // Display the results of hash operations
            System.out.println("SHA256: " + bytesToHex(sha256Result));
            System.out.println("RIPEMD160: " + bytesToHex(ripemd160Result));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Step 2: Generate ECDSA keypair
    private static ECKeyPair generateECDSAKeypair() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        return new ECKeyPair(privKey, pubKey);
    }

    // Step 3: Generate hashes based on the public key
    private static byte[] applySHA256(String input) throws Exception {
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");
        return sha256Digest.digest(hexStringToByteArray(input));
    }

    private static byte[] applyRIPEMD160(byte[] input) throws Exception {
        MessageDigest ripemd160Digest = MessageDigest.getInstance("RipeMD160");
        return ripemd160Digest.digest(input);
    }

    // Utility functions

    private static String bytesToHex(byte[] hashInBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

}

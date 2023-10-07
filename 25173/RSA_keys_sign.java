import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class RSA_keys_sign {
    public static void main(String args[]) throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(1024 * 2);

        KeyPair pair = keyPairGen.generateKeyPair();
        PrivateKey privKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        System.out.println("Keys generated");
        String privateKeyString = Base64.getEncoder().encodeToString(privKey.getEncoded());
        String publicKeyString = Base64.getEncoder().encodeToString(publicKey.getEncoded());

        System.out.println("RSA Private Key:");
        System.out.println(privateKeyString);

        System.out.println("\nRSA Public Key:");
        System.out.println(publicKeyString);

        Scanner sc = new Scanner(System.in);
        System.out.println("\nEnter some text");
        String msg = sc.nextLine();

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privKey);
        sign.update(msg.getBytes());
        byte[] signature = sign.sign();

        System.out.println("\nDigital signature for given text: " + new String(signature, "UTF8"));

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] input = msg.getBytes();
        cipher.update(input);
        byte[] cipherText = cipher.doFinal();

        System.out.println("\nEncrypted text:");
        System.out.println(new String(cipherText, "UTF8"));

        String signatureString = Base64.getEncoder().encodeToString(signature);
        System.out.println("\nDigital signature for given text (Base64): " + signatureString);

        String encryptedTextString = Base64.getEncoder().encodeToString(cipherText);
        System.out.println("\nEncrypted text (Base64): " + encryptedTextString);
    }
}

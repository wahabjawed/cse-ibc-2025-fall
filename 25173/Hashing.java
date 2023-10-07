import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Scanner;

public class Hashing {

    public static void main(String args[]) throws Exception {

        // Adding Bouncy Castle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Reading data from user
        Scanner sc = new Scanner(System.in);
        System.out.println("Enter the message");
        String message = sc.nextLine();
        hash512(message);
        hash256(message);
        hashRIPEMD160(message);

    }

    public static void hash512(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(message.getBytes());
        byte[] digest = md.digest();
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }
        System.out.println("Hex format for SHA-512 : " + hexString.toString());
    }

    public static void hash256(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(message.getBytes());
        byte[] digest = md.digest();
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }
        System.out.println("Hex format for SHA-256 : " + hexString.toString());
    }

    public static void hashRIPEMD160(String message) throws NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance("RipeMD160");
        md.update(message.getBytes());
        byte[] digest = md.digest();
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < digest.length; i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }
        System.out.println("Hex format for RIPEMD-160 : " + hexString.toString());
    }

}

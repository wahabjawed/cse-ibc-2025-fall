import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

  public class encrypted_message   {
        public static void main(String[] args)throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException  {

            // Generate an RSA key pair with a key size of 2048 bits
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
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

            // Initialize the Cipher for encryption using the public key
            Cipher encryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // Text to be encrypted
            String plaintext = "ismail";
            byte[] encryptedBytes = encryptCipher.doFinal(plaintext.getBytes());

            // Encode the encrypted bytes to Base64 for transmission/storage
            String encryptedBase64 = Base64.getEncoder().encodeToString(encryptedBytes);

            // Print or use the encrypted text
            System.out.println("Encrypted Text:");
            System.out.println(encryptedBase64);

            try {

                // Initialize a Signature object for signing using the private key
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);

                // Text to be signed
                String textToSign = "ismail";

                // Update the Signature object with the data to be signed
                signature.update(textToSign.getBytes());

                // Generate the digital signature
                byte[] digitalSignature = signature.sign();

                // Encode the digital signature to Base64 for transmission/storage
                String signatureBase64 = Base64.getEncoder().encodeToString(digitalSignature);

                // Print or use the digital signature
                System.out.println("Digital Signature:");
                System.out.println(signatureBase64);

                        //Reading data from user
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
        for (int i=0;i<digest.length;i++) {
            hexString.append(Integer.toHexString(0xFF & digest[i]));
        }
        System.out.println("Hex format : " + hexString.toString());

            } catch (Exception e) {
                e.printStackTrace();
            }


        }
    }


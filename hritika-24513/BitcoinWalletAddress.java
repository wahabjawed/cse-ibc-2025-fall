import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class BitcoinWalletAddress {

    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        java.security.Security.addProvider(new BouncyCastleProvider());

        // Step 2: Generate ECDSA keypair
        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);

        // Print Private and Public Key
        System.out.println("Private Key: " + privKey.toString(16));
        System.out.println("Public Key: " + pubKey.toString(16));

        // Compressed Public Key
        String bcPub = compressPubKey(pubKey);
        System.out.println("Compressed Public Key: " + bcPub);

        // Step 3: Generate hashes based on the public key
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] s1 = sha.digest(hexStringToByteArray(bcPub));

            MessageDigest rmd = MessageDigest.getInstance("RipeMD160");
            byte[] r1 = rmd.digest(s1);

            // Print Hashed Versions
            System.out.println("SHA256: " + bytesToHex(s1));
            System.out.println("RIPEMD160: " + bytesToHex(r1));


        } catch (Exception e) {
            e.printStackTrace();
        }
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

    private static String bytesToHex(byte[] hashInBytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < hashInBytes.length; i++) {
            sb.append(Integer.toString((hashInBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
}

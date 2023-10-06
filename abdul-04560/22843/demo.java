import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.MessageDigest;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

public class demo {

    public static void main(String[] args) {
        try {
            BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
            BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
            String bcPub = compressPubKey(pubKey);
            MessageDigest sha = MessageDigest.getInstance("SHA-256");

            byte[] s1 = sha.digest(hexStringToByteArray(bcPub));
            // Generate the RIPEMD-160 hash of the SHA-256 hash
            RIPEMD160Digest ripemd160 = new RIPEMD160Digest();
            byte[] ripemd160Hash = new byte[ripemd160.getDigestSize()];
            ripemd160.update(s1, 0, s1.length);
            ripemd160.doFinal(ripemd160Hash, 0);

            // Print the SHA-256 and RIPEMD-160 hashes
            System.out.println("SHA-256 hash: " + bytesToHex(s1));
            System.out.println("RIPEMD-160 hash: " + bytesToHex(ripemd160Hash));
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            System.err.println("Error generating hash: " + e.getMessage());
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
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
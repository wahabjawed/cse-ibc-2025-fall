import org.bitcoinj.core.Base58;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Security;

public class BitcoinAddress {

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);


        String bcPub = compressPubKey(pubKey);

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] s1 = sha.digest(hexStringToByteArray(bcPub));
        MessageDigest rmd = MessageDigest.getInstance("RipeMD160");
        byte[] r1 = rmd.digest(s1);

        byte[] r2 = new byte[r1.length + 1];
        r2[0] = 0;
        //System.arraycopy(r1, 0, r2, 1, r1.length);

        for (int i = 0; i < r1.length; i++) {
            r2[i + 1] = r1[i];
        }

        byte[] s2 = sha.digest(r2);
        byte[] s3 = sha.digest(s2);

        byte[] a1 = new byte[25];
        for (int i = 0; i < r2.length; i++) {
            a1[i] = r2[i];
        }

        for (int i = 0; i < 4; i++) {
            a1[21 + i] = s3[i];
        }

        String bitcoinAddress = Base58.encode(a1);
        System.out.println("Bitcoin Address: " + bitcoinAddress);

        System.out.println("Public Key: " + pubKey.toString(16));
        System.out.println("Private Key: " + privKey.toString(16));
    }

    public static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    private static String bytesToHex(byte[] hashInBytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : hashInBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
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

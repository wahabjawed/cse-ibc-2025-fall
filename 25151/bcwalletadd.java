import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.MessageDigest;

public class bcwalletadd {
    public static void main(String[] args) throws Exception {
        java.security.Security.addProvider(new BouncyCastleProvider());
        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);

        ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);
        byte[] bcPub= keyPair.getPublicKey().toByteArray();
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update(bcPub);
        byte[] s1= sha.digest();
        MessageDigest rmd = MessageDigest.getInstance("RipeMD160");

        byte[] r1 = rmd.digest(s1);
        System.out.println(Hex.toHexString(r1));
    }
}

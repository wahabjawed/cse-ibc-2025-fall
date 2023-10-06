import org.bitcoinj.core.Base58;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Keys;
import org.web3j.crypto.Sign;

import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;

//import static org.web3j.utils.Numeric.hexStringToByteArray;

public class assignment {
    public static void main(String[] args) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
//        // Step 2: Add BouncyCastleProvider to the list of security providers
//        Security.addProvider(new BouncyCastleProvider());
//
//        // Step 3: Verify that BouncyCastleProvider is added
//        for (Provider provider : Security.getProviders()) {
//            System.out.println(provider.getName());
//        }
        BigInteger privKey = Keys.createEcKeyPair().getPrivateKey();
//        System.out.println(privKey);

        String privateKeyHex = privKey.toString(16);
  //      System.out.println(privateKeyHex.length());
   //     System.out.println("Private key: " + privateKeyHex);
        BigInteger pubKey = Sign.publicKeyFromPrivate(privKey);
        ECKeyPair keyPair = new ECKeyPair(privKey, pubKey);


        String bcPub = compressPubKey(pubKey);
//        System.out.println(bcPub);
//        System.out.println(bcPub.length());

        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] s1 = sha.digest(hexStringToByteArray(bcPub));

        String hexString_sha = toHexString(s1);
        System.out.println("SHA256: " + hexString_sha);
        //System.out.println(hexString.length());

//        MessageDigest rmd = MessageDigest.getInstance("RipeMD160");
//
//        byte[] r1 = rmd.digest(s1);
//
//        String hexString_rip = toHexString(r1);
//        System.out.println("RipeMD160: " + hexString_rip);
//        System.out.println(hexString_rip.length());

        RIPEMD160Digest rmd = new RIPEMD160Digest();

        byte[] r1 = new byte[rmd.getDigestSize()];
        rmd.update(s1, 0, s1.length);
        rmd.doFinal(r1, 0);

        String hexString_rip = toHexString(r1);
        hexString_rip = hexString_rip.substring(24);
        System.out.println("RIPEMD160: " + hexString_rip);
//        System.out.println(hexString_rip.length());

        hexString_rip = "00"+hexString_rip;
        System.out.println("RIPEMD160 with network code: " + hexString_rip);
//        System.out.println(toHexString(r2));


        byte[] s2 = sha.digest(hexStringToByteArray(hexString_rip));

        byte[] s3 = sha.digest(s2);

        String hexString_checksum = toHexString(s3);
        System.out.println(hexString_checksum);

        byte[] sha256Bytes = hexStringToByteArray(hexString_checksum);

        // Create a new byte array to store the first 4 bytes
        byte[] first4Bytes = new byte[4];

        // Copy the first 4 bytes from the SHA256 hash byte array to the new byte array
        System.arraycopy(sha256Bytes, 0, first4Bytes, 0, 4);

        // Convert the new byte array to a hexadecimal string
        String first4BytesHex = toHexString(first4Bytes);

        // Store the hexadecimal string in a string variable
        String result = first4BytesHex;
        result = result.substring(56);

        System.out.println("first 4 bytes of checksum: "+result);

        String complete_CheckSum = hexString_rip+result;

        System.out.println("Complete Checksum after appending with ripmd: "+ complete_CheckSum);

       String bitcoin_address = Base58.encode(hexStringToByteArray(complete_CheckSum));

        System.out.println("Bitcoin Address: "+bitcoin_address);



    }
    public static String compressPubKey(BigInteger pubKey) {
        String pubKeyYPrefix = pubKey.testBit(0) ? "03" : "02";
        String pubKeyHex = pubKey.toString(16);
        String pubKeyX = pubKeyHex.substring(0, 64);
        return pubKeyYPrefix + pubKeyX;
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    public static String toHexString(byte[] hash) {
        BigInteger number = new BigInteger(1, hash);
        StringBuilder hexString = new StringBuilder(number.toString(16));
        while (hexString.length() < 64) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }

}


import javax.crypto.spec.DHParameterSpec;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.SecretKey;
import javax.crypto.KeyAgreement;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.io.IOException;


public class DiffieHellman {

    public static DHParameterSpec createAlgoParameters()
    {
        try {
            DHParameterSpec dhSkipParamSpec;
            System.err.println("Creating Diffie-Hellman parameters (takes VERY long) ...");
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(512);
            AlgorithmParameters params = paramGen.generateParameters();
            dhSkipParamSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
            return dhSkipParamSpec;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InvalidParameterSpecException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }
        return null;
    }

    public static KeyPair generateKeyPair(DHParameterSpec dhSkipParamSpec)
    {
        try {
            KeyPairGenerator KpairGen = KeyPairGenerator.getInstance("DH");
            KpairGen.initialize(dhSkipParamSpec);
            KeyPair Kpair = KpairGen.generateKeyPair();
            return Kpair;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }
        return null;
    }


    public static String getPubKeyInString(PublicKey pKey)
    {
        byte[] encoded=pKey.getEncoded();
        String pubKeyInString=new sun.misc.BASE64Encoder().encode(encoded);
        return pubKeyInString;
    }

    public static PublicKey getPubKeyFromSentString(String extractedKey)
    {
        try {
            byte[] encoded = new sun.misc.BASE64Decoder().decodeBuffer(extractedKey);
            KeyFactory KeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(encoded);
            PublicKey pubKey = KeyFac.generatePublic(x509KeySpec);
            return pubKey;
        } catch (IOException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }
        return null;
    }

    public static DHParameterSpec getDHParametersFromExistingKey(PublicKey pKey)
    {
        DHParameterSpec dhParamSpec = ((DHPublicKey)pKey).getParams();
        return dhParamSpec;
    }

    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }
        /*
     * Converts a byte array to hex string
     */
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

	int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
	     if (i < len-1) {
		 buf.append(":");
	     }
        }
        return buf.toString();
    }

    public static SecretKey generateSecretKey(PrivateKey key1, PublicKey key2)
    {
        try {
            KeyAgreement KeyAgree = KeyAgreement.getInstance("DH");
            KeyAgree.init(key1);
            KeyAgree.doPhase(key2, true);
            SecretKey DesKey = KeyAgree.generateSecret("DES");
            System.err.println("The generated diffie-hellman key is : ");
            System.out.println(toHexString(DesKey.getEncoded()));
            return DesKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (InvalidKeyException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        } catch (IllegalStateException e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }
        return null;
    }

}

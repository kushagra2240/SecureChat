
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;



public class generateRSA {
    int id;
    KeyPair rsaPair;

    public generateRSA(int a)
	{
       	id=a;
       	rsaPair=RSA.generateRsaKeyPair();
       	RSA.writeKey(id+".pub", rsaPair.getPublic().getEncoded());
       	RSA.writeKey(id+".pri", rsaPair.getPrivate().getEncoded());
    }

    public static void main(String args[])
	{
    	Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    	generateRSA A=new generateRSA(1);
    	generateRSA B=new generateRSA(2);
    }
}

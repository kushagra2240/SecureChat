import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import com.sun.rsasign.i;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;


public class OakleyInitiator {
	int id_of_A, id_of_B;
    DHParameterSpec dhpSpec;
    KeyPair dhPair;
    PublicKey dhKeyB;
    SecretKey desKey;

	String cookieA,keyA,nonceA;
	String initiatorMsg1=new String();
	String initiatorMsg2=new String();
	
	public OakleyInitiator(int idA, int idB,double secretValue)
	{
		id_of_A=idA;
		id_of_B=idB;
		cookieA=CommonFunctions.generateCookie(secretValue,id_of_B);
		nonceA=CommonFunctions.generateNonce();
        dhpSpec=DiffieHellman.createAlgoParameters();
        dhPair=DiffieHellman.generateKeyPair(dhpSpec);
        keyA=DiffieHellman.getPubKeyInString(dhPair.getPublic());
	}
	
	public String sendMsg1()
	{

		initiatorMsg1=new String();
		initiatorMsg1+="A="+id_of_A+",B="+id_of_B+",CK_A="+cookieA;
		initiatorMsg1+=",keyA="+keyA+",NonceA="+nonceA;
		String plainText=new String();
		plainText+=id_of_A+""+id_of_B+nonceA+keyA;
//        System.out.println("plain text in initiator is : "+plainText);
//		initiatorMsg1+=",Signed="+ new String(RSA.rsaCrypt(plainText.getBytes(),Cipher.ENCRYPT_MODE, RSA.getPrivateKey(id_of_A)));
        byte[] encrypted= RSA.rsaCrypt(plainText.getBytes(),Cipher.ENCRYPT_MODE, RSA.getPrivateKey(id_of_A));
        String encryptedStr= new sun.misc.BASE64Encoder().encode(encrypted);
		initiatorMsg1+=",Signed="+ encryptedStr;
		return initiatorMsg1;
	}

    public String extract(String msg, String param)
    {
        try{

        int StartIndex=msg.indexOf(param)+param.length()+1;
        if(msg.indexOf(param)==-1)
        {
            System.out.println("Parameter does not exist in list");
            return null;
        }
        String substr=msg.substring(StartIndex);
        int endIndex;

        endIndex=substr.indexOf(",");
        if(param.equals("Signed"))
            return substr;

        return substr.substring(0,endIndex);
        }catch(Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }


//	public String extract(String msg, String param)
//	{
//		int StartIndex=msg.indexOf(param)+param.length()+1;
//		String substr=msg.substring(StartIndex);
//		int endIndex;
//		endIndex=substr.indexOf(",");
//		if(endIndex==-1)
//			return substr;
//		return substr.substring(0,endIndex);
//	}

	//authentic =>true else false
	public boolean authenticateMsg2(char[] msg1)
	{
        try {
            String msg=new String(msg1);
            if(msg.indexOf('\0')!=-1)
                msg=msg.substring(0,msg.indexOf('\0'));
            System.err.println("Second message in oakley sequence (This is to be authenticated here): ");
            int idB=Integer.parseInt(extract(msg,"B"));
            String plainText=extract(msg,"B")+extract(msg,"A")+nonceA+extract(msg,"NonceB")+extract(msg,"keyB")+keyA;
            String encryptedMsg=extract(msg,"Signed");
            byte[] encrypted=new sun.misc.BASE64Decoder().decodeBuffer(encryptedMsg);;
            byte[] decrypted=RSA.rsaCrypt(encrypted,Cipher.DECRYPT_MODE,RSA.getPublicKey(idB));
            String decryptedText=new String(decrypted);
            System.out.println("expected plain text is : "+plainText);
            System.out.println("decrypted text is : "+decryptedText);
//            String decryptedText=new String(RSA.rsaCrypt(extract(msg, "Signed").getBytes(), Cipher.DECRYPT_MODE,RSA.getPublicKey(idB)));
            if(decryptedText.equals(plainText))
            {
                dhKeyB=DiffieHellman.getPubKeyFromSentString(extract(msg,"keyB"));
                desKey=DiffieHellman.generateSecretKey(dhPair.getPrivate(),dhKeyB);
                return true;
            }

        } catch (Exception e) {
            e.printStackTrace();  //To change body of catch statement use Options | File Templates.
        }
            return false;
    }
	
	public String sendMsg3(char[] msg1)
	{
        String msg=new String(msg1);
        if(msg.indexOf('\0')!=-1)
            msg=msg.substring(0,msg.indexOf('\0'));
		String cookieB=extract(msg,"CK_B");
		String nonceB=extract(msg,"NonceB");
		String keyB=extract(msg,"keyB");
		initiatorMsg2=new String();
		initiatorMsg2+="A="+id_of_A+",B="+id_of_B+",CK_B="+cookieB+",CK_A="+cookieA;
		initiatorMsg2+=",keyA="+keyA+",NonceA="+nonceA+",NonceB="+nonceB;
		String plainText=new String();
		plainText+=id_of_A+""+id_of_B+nonceA+nonceB+keyA+keyB;
        byte[] encrypted= RSA.rsaCrypt(plainText.getBytes(),Cipher.ENCRYPT_MODE, RSA.getPrivateKey(id_of_A));
        String encryptedStr= new sun.misc.BASE64Encoder().encode(encrypted);
		initiatorMsg2+=",Signed="+ encryptedStr;
		return initiatorMsg2;
	}
	
    public SecretKey getDESKey()
    {
        return desKey;
    }


}

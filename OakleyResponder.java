import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import java.security.KeyPair;
import java.security.PublicKey;


public class OakleyResponder {
	int id_of_A, id_of_B;
	String cookieB,keyB,nonceB;
    DHParameterSpec dhpSpec;
    KeyPair dhPair;
    PublicKey dhKeyA;
    SecretKey desKey;
    double SecVal;

	String initiatorMsg1=new String();
	String initiatorMsg2=new String();
	
	public OakleyResponder(int idB,double secretValue)
	{

		id_of_B=idB;
        SecVal=secretValue;
		//		keyB=kB;
		nonceB=CommonFunctions.generateNonce();
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

	//authentic =>true else false
	public boolean authenticateMsg1(char[] msg1)
	{
        try{
        String msg=new String(msg1);
        if(msg.indexOf('\0')!=-1)
            msg=msg.substring(0,msg.indexOf('\0'));
        System.err.println("Firt message in oakley key exchange (this is to be authenticated here) : ");
        System.out.println(msg);
        int idA=Integer.parseInt(extract(msg,"A"));
		System.out.println("Inside authenticate module now!");
		String plainText=extract(msg,"A")+extract(msg,"B")+extract(msg, "NonceA")+extract(msg,"keyA");

        String encryptedMsg=extract(msg,"Signed");
        byte[] encrypted=new sun.misc.BASE64Decoder().decodeBuffer(encryptedMsg);;
        byte[] decrypted=RSA.rsaCrypt(encrypted,Cipher.DECRYPT_MODE,RSA.getPublicKey(idA));
        String decryptedText=new String(decrypted);
        System.out.println("expected plain text is : " + plainText);
        System.out.println("decrypted text is : "+decryptedText);
		if(decryptedText.equals(plainText))
        {
            id_of_A=idA;
            cookieB=CommonFunctions.generateCookie(SecVal, idA);
            dhKeyA=DiffieHellman.getPubKeyFromSentString(extract(msg,"keyA"));
            dhpSpec=DiffieHellman.getDHParametersFromExistingKey(dhKeyA);
            dhPair=DiffieHellman.generateKeyPair(dhpSpec);
            keyB=DiffieHellman.getPubKeyInString(dhPair.getPublic());
			return true;
        }
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
        	return false;
	}

    public boolean authenticateMsg3(char[] msg1)
    {
       try{
        String msg=new String(msg1);
        if(msg.indexOf('\0')!=-1)
            msg=msg.substring(0,msg.indexOf('\0'));
        System.err.println("Third message in oakley key exchange (this is to be authenticated here) : ");
        System.out.println(msg);
        int idA=Integer.parseInt(extract(msg,"A"));
		System.out.println("Inside authenticate module now!");
		String plainText=extract(msg,"A")+id_of_B+extract(msg, "NonceA")+nonceB+extract(msg,"keyA")+keyB;

        String encryptedMsg=extract(msg,"Signed");
        byte[] encrypted=new sun.misc.BASE64Decoder().decodeBuffer(encryptedMsg);;
        byte[] decrypted=RSA.rsaCrypt(encrypted,Cipher.DECRYPT_MODE,RSA.getPublicKey(idA));
        String decryptedText=new String(decrypted);
        System.out.println("expected plain text is : " + plainText);
        System.out.println("decrypted text is : "+decryptedText);
		if(decryptedText.equals(plainText))
        {
            desKey=DiffieHellman.generateSecretKey(dhPair.getPrivate(),dhKeyA);
			return true;
        }
        }catch(Exception e)
        {
            e.printStackTrace();
        }
        return false;
    }

	public String sendMsg2(char[] msg1)
	{

        String msg=new String(msg1);
        if(msg.indexOf('\0')!=-1)
            msg=msg.substring(0,msg.indexOf('\0'));
		String cookieA=extract(msg,"CK_A");
		String nonceA=extract(msg,"NonceA");
		String keyA=extract(msg,"keyA");
		initiatorMsg2=new String();
		initiatorMsg2+="B="+id_of_B+",A="+id_of_A+",CK_B="+cookieB+",CK_A="+cookieA;
		initiatorMsg2+=",keyB="+keyB+",NonceA="+nonceA+",NonceB="+nonceB;
		String plainText=new String();
		plainText+=id_of_B+""+id_of_A+nonceA+nonceB+keyB+keyA;
        byte[] encrypted= RSA.rsaCrypt(plainText.getBytes(),Cipher.ENCRYPT_MODE, RSA.getPrivateKey(id_of_B));
        String encryptedStr= new sun.misc.BASE64Encoder().encode(encrypted);
		initiatorMsg2+=",Signed="+ encryptedStr;
		return initiatorMsg2;
	}

    public SecretKey getDESKey()
    {
        return desKey;
    }



}

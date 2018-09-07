
import javax.crypto.Cipher;
import java.security.Key;
import java.io.ByteArrayOutputStream;


public class DES {

    public static byte[] crypt(byte[] text, int type, Key key)
        {

            ByteArrayOutputStream out = null;
            try {
//                Cipher desCipher=Cipher.getInstance("DES/ECB/PKCS5Padding");
                Cipher desCipher =Cipher.getInstance("DES");
//			byte[] text=plainText.getBytes();
                desCipher.init(type, key);
//                int bzise = desCipher.getBlockSize();
                out = new ByteArrayOutputStream();
                out.write(desCipher.doFinal(text));
//                int s = desCipher.getBlockSize();
//                int r = 0;
//                for (int t = 0; t < text.length; t += s) {
//                    if (text.length - t <= s) {
//                        r = text.length - t;
//                    } else {
//                        r = s;
//                    }
//                    out.write(desCipher.doFinal(text, t, r));
//                }
                out.flush();
                out.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return out.toByteArray();
        }

}

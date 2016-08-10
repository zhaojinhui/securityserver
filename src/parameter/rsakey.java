package parameter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

// use server RSA private key to decrypt
public class rsakey {
	public String rsadecrypt(String  m) {
		try {
			byte[] msg=m.getBytes("ISO-8859-1");
			FileInputStream rsaStream = new FileInputStream("d:/RSAprivate.txt");
			ObjectInputStream rsaobjStream=new ObjectInputStream(rsaStream);
			Key rsaKey=(Key)rsaobjStream.readObject();
			Cipher cipher=Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, rsaKey);
			byte[] ciphertext=cipher.doFinal(msg);
			String result=new String(ciphertext,"ISO-8859-1");
			return result;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}

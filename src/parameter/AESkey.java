package parameter;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// manage the AES operation
public class AESkey {
	
	//encrypt with user's hashed password
	public  String enhashpwd(String password, String m) {
		
		try {
			byte[] bytes=m.getBytes("ISO-8859-1");
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128,new SecureRandom(password.getBytes()));
			SecretKey secretKey=kgen.generateKey();
			
			Cipher cipher=Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] enmsg=cipher.doFinal(bytes);
			String result=new String(enmsg,"ISO-8859-1");
			return result;
		}  catch (NoSuchAlgorithmException e) {
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
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	//decrypt with user's hashed password
	public  String dehashpwd(String password, String m) {
		
		try {
			byte[] bytes=m.getBytes("ISO-8859-1");
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128,new SecureRandom(password.getBytes()));
			SecretKey secretKey=kgen.generateKey();
			
			Cipher cipher=Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] demsg=cipher.doFinal(bytes);
			String result=new String(demsg,"ISO-8859-1");
			return result;
		}  catch (NoSuchAlgorithmException e) {
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
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	//AES enryption
	public String AESencrypt(SecretKeySpec DHAESkey, String m) {
		Cipher cipher;
		try {
			byte[] bytes=m.getBytes("ISO-8859-1");
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, DHAESkey);
			byte[] ciphertext=cipher.doFinal(bytes);
			String result=new String(ciphertext,"ISO-8859-1");
			return result;
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
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	//AES decrypt
	public String AESdecrypt(SecretKeySpec DHAESkey, String m) {
		Cipher cipher;
		try {
			byte[] bytes=m.getBytes("ISO-8859-1");
			cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, DHAESkey);
			byte[] ciphertext=cipher.doFinal(bytes);
			String result=new String(ciphertext,"ISO-8859-1");
			return result;
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
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}

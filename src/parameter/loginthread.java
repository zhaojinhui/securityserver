package parameter;
import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.HashMap;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import static parameter.mainserver.syncookies;
import static parameter.mainserver.userandip;
import static parameter.mainserver.userandkey;
import static parameter.mainserver.timestamps;
import static parameter.mainserver.ipanduser;
import static parameter.mainserver.loginuers;
import static parameter.mainserver.banedusers;
import static parameter.mainserver.userandport;

// respond to the user login request
public class loginthread implements Runnable {
	
	Socket socket;	
	String username;
	String hashpwd;
	String syncookie;
	String timestamp;
	rsakey rsa;
	AESkey aes;
	int handshaketimes;
	KeyPair DHKeyPair;
	SecretKeySpec DHAESkey;
	String clientaddress;
	String recmsg;
	// initiate the user input message and get the socket instance
	public loginthread(Socket s, String msg) {
		socket=s;
		recmsg=msg;
	}

	@Override
	public void run() {
		handshaketimes=0;
		try {
			// initiate AES key, RSA key, and also input output stream
			aes=new AESkey();
			rsa=new rsakey();
			InputStream in = socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			clientaddress=socket.getInetAddress().getHostAddress();
			String sendmsg=null;
			String key=null;
			String judge=null;
			int count=0;
			boolean looporstop;
			username=recmsg.substring(5);
			// if the user is bane by server then wait until it is removed from block list
			if(banedusers.containsKey(username))
			{
				try {
					Thread.sleep(3000);
					banedusers.remove(username);
				} catch (InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
			looporstop=true;
			while(looporstop)
			{
				// if the username has already login then send repeat login back
				if(loginuers.containsKey(username))
				{					
					outStream.writeUTF("repeat login");
					count++;
					// more than 5 times forbid to login 
					if(count==5)
					{
						banedusers.put(username, "baned");
						looporstop=false;
					}
					recmsg=inStream.readUTF();
					username=recmsg.substring(5);
				}
				else
				if(handshaketimes==0)
				{
					// if the user is in the server user library
					if(findusername(username))
					{
					    // add the login user to current login user map
						ipanduser.put(clientaddress, username);
						userandip.put(username, clientaddress);
						// generate a one session cookie to prevent DOS
						String puzzle=generatepuzzle();
						syncookie=generatecookies(puzzle);
						syncookies.put(username, syncookie);
						// send syncookie and timestamp back to the user
						sendmsg=syncookie+"|"+generatetimestamp()+"|";
						outStream.writeUTF(sendmsg);
						handshaketimes++;
						
						recmsg=inStream.readUTF();
					}
					// if username is not a valid user
					else {
						outStream.writeUTF("wrong user");
						count++;
						if(count==5)
						{
							banedusers.put(username, "baned");
							looporstop=false;
						}
						recmsg=inStream.readUTF();
						recmsg=rsa.rsadecrypt(recmsg);
						username=recmsg.substring(5);
					}
				}
				else 
				if(handshaketimes==1)
				{	
					recmsg=rsa.rsadecrypt(recmsg);
					judge=syncookie+username+hashpwd+addtimestamp();
					// if the message is send by the right user and the password is right 
					if(recmsg.startsWith(judge))
					{
						handshaketimes++;
						// use user hashed passwrod to send the diff hellman key to the client 
						// to generate a one time session key between client and server
						sendmsg=syncookie+addtimestamp()+DHpub();
						sendmsg=aes.enhashpwd(hashpwd, sendmsg);
						outStream.writeUTF(sendmsg);
						recmsg=inStream.readUTF();
					}
					// if password is not right
					else {
						banedusers.put(username, "login fail");
						outStream.writeUTF("wrong password");
						looporstop=false;
					}
				}
				else 
				if(handshaketimes==2)
				{
					recmsg=aes.dehashpwd(hashpwd, recmsg);
					judge=syncookie+addtimestamp();
					// if the message comes from the right user
					if(recmsg.startsWith(judge))
					{
						// generate the session key between client and server
						// and tell the client the key generation is successful
						String pubdh=recmsg.substring(judge.length());
						DHAESkey=generateAESkey(pubdh);
						userandkey.put(username,DHAESkey);
						sendmsg=aes.AESencrypt(DHAESkey, syncookie+" successful");
						outStream.writeUTF(sendmsg);
						handshaketimes++;
						recmsg=inStream.readUTF();
						recmsg=aes.dehashpwd(hashpwd, recmsg);
						judge=syncookie+addtimestamp();
						// record the client server port and mark the user as online
						if(recmsg.startsWith(judge))
						{
							recmsg=recmsg.substring(judge.length());
							userandport.put(username, Integer.parseInt(recmsg));
							loginuers.put(username, "oline");
						}
						else
						{
							System.out.println("the client is not trusted");
						}
						looporstop=false;
					}
					else {
						System.out.println("the client is not trusted");
						looporstop=false;
					}
				}
			}		
		} catch (IOException e) {
			System.out.println("clientis something wrong");
			ipanduser.remove(clientaddress);
			userandip.remove(username);
			syncookies.remove(username);
		} 

	}
	
	//generate time stamp
	private String generatetimestamp() {
		Timestamp ts=new Timestamp(System.currentTimeMillis());
		timestamp=ts.toString();
		timestamps.put(username, timestamp);
		return timestamp;
	}
	
	//add time stamp
	private String addtimestamp() {
		String times=String.valueOf(handshaketimes);
		String temp=timestamp+times;
		return temp;
	}

	//check the register user in the server user library
	private boolean findusername(String msg) {
		try {
			FileReader reader=new FileReader("d:/list.txt");
			BufferedReader bf=new BufferedReader(reader);
			String temp;
			while((temp=bf.readLine())!=null)
			{
				// if the username is in the user library called list.txt
				if(temp.equals(msg))
				{
					// from the username.txt get user hased password
					String fileName="d:/"+username+".txt";
					File file=new File(fileName);
					InputStream inputStream=new FileInputStream(file);
					byte[] aa=new byte[25];
					int t=inputStream.read(aa);
					byte[] result=new byte[t-4];
					System.arraycopy(aa, 4, result, 0, t-4);
					hashpwd=new String(result,"ISO-8859-1");
					return true;
				}
			}
			bf.close();
			reader.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
	
	//generate puzzle
	private String generatepuzzle() {
		int a=(int) (Math.random()*10000);
		String temp=String.valueOf(a);
		return temp;
	}
	
	//generate SYN cookies
	private String generatecookies(String puzzle) {	
		try {
			String temp=username+puzzle+hashpwd;
			MessageDigest tempdigest=MessageDigest.getInstance("SHA-1");
			byte[] bt=tempdigest.digest(temp.getBytes("ISO-8859-1"));
			String result=new String(bt,"ISO-8859-1");
			return result;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    return null;
	}
	
	//generate DH key pair
	private void generateDHKeyPair() {
		try {
			KeyPairGenerator keGenerator=KeyPairGenerator.getInstance("DH");
			keGenerator.initialize(512);
			DHKeyPair=keGenerator.genKeyPair();
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} 
	}
	
	//get DH public key
	private String DHpub() {
		try {
			generateDHKeyPair();
			byte[] temp=DHKeyPair.getPublic().getEncoded();
			String pubkey;
			pubkey = new String(temp, "ISO-8859-1");
			return pubkey;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	//generate session key
	private SecretKeySpec generateAESkey(String m) {
		KeyFactory keyFactory;
		try {
			byte[] msg=m.getBytes("ISO-8859-1");
			keyFactory = KeyFactory.getInstance("DH");
			EncodedKeySpec pubKeySpec=new X509EncodedKeySpec(msg);
			PublicKey pKey=keyFactory.generatePublic(pubKeySpec);
			
			KeyAgreement bKeyAgreement=KeyAgreement.getInstance("DH");
		    bKeyAgreement.init(DHKeyPair.getPrivate());
		    bKeyAgreement.doPhase(pKey, true);
		    
		    MessageDigest bdigest=MessageDigest.getInstance("MD5");
		    byte[] bt=bdigest.digest(bKeyAgreement.generateSecret());
		    DHAESkey=new SecretKeySpec(bt, "AES");
			return DHAESkey;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return null;
	}
}

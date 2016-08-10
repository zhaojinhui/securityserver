package parameter;
import static parameter.mainserver.ipanduser;
import static parameter.mainserver.loginuers;
import static parameter.mainserver.syncookies;
import static parameter.mainserver.userandip;
import static parameter.mainserver.userandkey;
import static parameter.mainserver.timestamps;
import static parameter.mainserver.userandport;
import static parameter.mainserver.clientusername;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

// respond to client list request and send the current login users to client 
public class listthread implements Runnable {
	String recmsg;
	Socket socket;
	String tusername;
	String username;
	AESkey aes;
	SecretKeySpec DHAESkey;
	String clientAddress;
	public listthread(Socket s, String msg) {
		recmsg=msg;
		socket=s;
	}

	@Override
	public void run() {
		try {
			aes=new AESkey();
			InputStream in=socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			String sendmsg=null;
			String judge=null;
			// according to the client address to get the client name
			clientAddress=socket.getInetAddress().getHostAddress();
			tusername=getusername();
			clientusername=tusername;
			String ip=userandip.get(tusername);
			int port=userandport.get(tusername);
			DHAESkey=userandkey.get(tusername);
			int length=5+tusername.length();
			recmsg=recmsg.substring(length);
			recmsg=aes.AESdecrypt(DHAESkey, recmsg);
			judge=syncookies.get(tusername)+timestamps.get(tusername);
			// if the user is the right user
			if(recmsg.startsWith(judge))
			{
				// user the session key to encrypt the name list and send to the client
				Iterator iterator=loginuers.entrySet().iterator();
				while(iterator.hasNext())
				{
					Map.Entry entry = (Map.Entry) iterator.next();
					String user = (String) entry.getKey();
					if(sendmsg==null)
					{
						sendmsg=user;
					}
					else
					{
						sendmsg=sendmsg+"|"+user;
					}
				}
				sendmsg=judge+sendmsg;
				sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
				outStream.writeUTF(sendmsg);
			}
			else {
				System.out.println("the cient should not be truested");
			}
				
		} catch (IOException e) {
			System.out.println("there is something wrong with"+tusername);
			syncookies.remove(username);
			userandip.remove(username);
			timestamps.remove(username);
			userandkey.remove(username);
			ipanduser.remove(clientAddress);
			loginuers.remove(username);
			userandport.remove(username);
		}
		
	}
	// get the client name according to the client address
	private String getusername() {
		byte[]receiveinfo = null;
		int num=0;
		int start=0;
		try {
			byte[] msg=recmsg.getBytes("ISO-8859-1");
			for(int i=0;i<msg.length;i++)
			{
				if(msg[i]!='|')
				{
					num++;
				}
				else{
					receiveinfo=new byte[num];
					System.arraycopy(msg, start, receiveinfo, 0, num);
					break;
				}
			}
			String result=new String(receiveinfo,"ISO-8859-1");
			result=result.substring(4);
			return result;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

}

package parameter;
import static parameter.mainserver.syncookies;
import static parameter.mainserver.timestamps;
import static parameter.mainserver.userandip;
import static parameter.mainserver.userandkey;
import static parameter.mainserver.ipanduser;
import static parameter.mainserver.loginuers;
import static parameter.mainserver.userandport;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketAddress;
import javax.crypto.spec.SecretKeySpec;

// respond to client log off request
public class logoffthread implements Runnable {

	String recmsg;
	Socket socket;
	String username;
	AESkey aes;
	SecretKeySpec DHAESkey;
	String clientAddress;

	public logoffthread(Socket s, String msg) {
		socket=s;
		recmsg=msg;
	}

	@Override
	public void run() {
		try {
			aes=new AESkey();
			
			OutputStream out=socket.getOutputStream();
			DataOutputStream outStream=new DataOutputStream(out);
			clientAddress=socket.getInetAddress().getHostAddress();
			String sendmsg=null;
			String judge=null;
			// receive client's logoff request 
			if(recmsg.startsWith("logoff"))
			{
				//username=ipanduser.get(clientAddress);
				username=getusername();
				DHAESkey=userandkey.get(username);
				int length=7+username.length();
				recmsg=recmsg.substring(length);
				recmsg=aes.AESdecrypt(DHAESkey, recmsg);
				judge=syncookies.get(username)+timestamps.get(username);
				// if the user is the right user
				if(recmsg.startsWith(judge))
				{
					// tell the user log off success
					sendmsg=syncookies.get(username)+"logoff success"+timestamps.get(username);
					sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
					// remove all the relevant information about this user
					syncookies.remove(username);
					userandip.remove(username);
					timestamps.remove(username);
					userandkey.remove(username);
					ipanduser.remove(clientAddress);
					loginuers.remove(username);
					userandport.remove(username);
					outStream.writeUTF(sendmsg);
				}
				else {
					System.out.println("the user is not in the list");
				}
			}
		} catch (IOException e) {
			System.out.println("there is something wrong with server");
			syncookies.remove(username);
			userandip.remove(username);
			timestamps.remove(username);
			userandkey.remove(username);
			ipanduser.remove(clientAddress);
			loginuers.remove(username);
			userandport.remove(username);
		}
	}
	
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
			result=result.substring(6);
			return result;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}

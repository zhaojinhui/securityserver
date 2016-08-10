package parameter;
import static parameter.mainserver.syncookies;
import static parameter.mainserver.userandip;
import static parameter.mainserver.userandkey;
import static parameter.mainserver.timestamps;
import static parameter.mainserver.ipanduser;
import static parameter.mainserver.userandport;
import static parameter.mainserver.userandip;
import static parameter.mainserver.loginuers;
import static parameter.mainserver.clientusername;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.Iterator;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

// respond to the client communication to other client request
// send the request client port, address, one time public key and time stamp to target client
// send the target client port, address, one time public key and time stamp to the request client
public class visittargetthread implements Runnable {
	String recmsg;
	Socket socket;
	String tusername;
	String username;
	AESkey aes;
	SecretKeySpec DHAESkey;
	public visittargetthread(Socket s, String msg) {
		recmsg=msg;
		socket=s;
	}

	@Override
	public void run() {
		String request = null;
		OutputStream out=null;
		String sendmsg=null;
		DataOutputStream outStream=null;
		try {
			aes=new AESkey();
			
			InputStream in=socket.getInputStream();
			DataInputStream inStream=new DataInputStream(in);
			out=socket.getOutputStream();
			outStream=new DataOutputStream(out);
			String pubkey = null;
			String judge=null;
			
			// get target client information from other client request 
			tusername=getusername();
			clientusername=tusername;
			DHAESkey=userandkey.get(tusername);
			int length=5+tusername.length();
			recmsg=recmsg.substring(length);
			recmsg=aes.AESdecrypt(DHAESkey, recmsg);
			judge=syncookies.get(tusername)+timestamps.get(tusername);
			if(recmsg.startsWith(judge))
			{
				request=recmsg.substring(judge.length());
				int count=0;
				// if the current login user don't have the target client
				while(!loginuers.containsKey(request))
				{
					count++;
					sendmsg="wrong request";
					sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
					outStream.writeUTF(sendmsg);
					recmsg=inStream.readUTF();
					recmsg=aes.AESdecrypt(DHAESkey, recmsg);
					request=recmsg.substring(judge.length());
					if(count==5)
						break;
				}
				if(count<5)
				{
					sendmsg="legal";
					sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
					outStream.writeUTF(sendmsg);
					
					// get the request client's ip and port who want to talk
					String ip=userandip.get(request);
					int port=userandport.get(request);
					
					recmsg=inStream.readUTF();
					recmsg=aes.AESdecrypt(DHAESkey, recmsg);
					if(recmsg.startsWith(judge))
					{
						recmsg=recmsg.substring(judge.length());
						pubkey=recmsg.substring(request.length()+1);
						// initiate the new input output stream and socket with the target client 
						Socket newsocket=new Socket(ip,port);
						InputStream newin=newsocket.getInputStream();
						DataInputStream newinStream=new DataInputStream(newin);
						OutputStream newout=newsocket.getOutputStream();
						DataOutputStream newoutStream=new DataOutputStream(newout);
						// send the target client the request client's information 
						sendmsg=syncookies.get(request)+timestamps.get(request)+tusername+"|"+pubkey;
						sendmsg=aes.AESencrypt(userandkey.get(request), sendmsg);
						sendmsg="visit"+sendmsg;
						newoutStream.writeUTF(sendmsg);
						
						// get target client information and sent 
						recmsg=newinStream.readUTF();
						recmsg=aes.AESdecrypt(userandkey.get(request), recmsg);
						judge=syncookies.get(request)+timestamps.get(request);
						if(recmsg.startsWith(judge))
						{
							// send the target client public key to request client 
							recmsg=recmsg.substring(judge.length());
							pubkey=recmsg;
							sendmsg=syncookies.get(tusername)+timestamps.get(tusername)+pubkey;
							sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
							outStream.writeUTF(sendmsg);
							// send ip
							sendmsg=syncookies.get(tusername)+timestamps.get(tusername)+ip;
							sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
							outStream.writeUTF(sendmsg);
							// send port
							sendmsg=syncookies.get(tusername)+timestamps.get(tusername)+String.valueOf(port);
							sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
							outStream.writeUTF(sendmsg);
						}
						else {
							System.out.println("the cient should not be truested");
						}
					}
					
				}
				else {
					
				}
			}
			else {
				System.out.println("the cient should not be truested");
			}
				
		} catch (IOException e) {
			System.out.println("the request client is something wrong");
			loginuers.remove(request);
			sendmsg="clients wrong";
			sendmsg=aes.AESencrypt(DHAESkey, sendmsg);
			try {
				outStream.writeUTF(sendmsg);
			} catch (IOException e1) {
				loginuers.remove(tusername);
				loginuers.put(request, "online");
			}
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
			result=result.substring(4);
			return result;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return null;
	}

}
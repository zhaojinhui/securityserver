package parameter;
import static parameter.mainserver.ipanduser;
import static parameter.mainserver.loginuers;
import static parameter.mainserver.syncookies;
import static parameter.mainserver.timestamps;
import static parameter.mainserver.userandip;
import static parameter.mainserver.userandkey;
import static parameter.mainserver.userandport;

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
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.spec.SecretKeySpec;

// this is the main process
public class mainserver {
	// record current login users and their ip address
	public static HashMap<String, String> userandip;
	public static HashMap<String, String> ipanduser;
	
	// record client and their syncookies 
	public static HashMap<String, String> syncookies;
	
	// record client and their session keys with server
	public static HashMap<String, SecretKeySpec> userandkey;
	
	// record client and their timestamps
	public static HashMap<String, String> timestamps;
	
	// record current login users
	public static HashMap<String, String> loginuers;
	
	// if a user try too many wrong password then it will be added here
	public static HashMap<String, String> banedusers;
	
	// record current login users and their port 
	public static HashMap<String, Integer> userandport;
	
	public static String clientusername;
	public static void main(String[] args) {
		ServerSocket server = null;
		rsakey rsa=new rsakey();
		userandip=new HashMap<String, String>();
		syncookies=new HashMap<String, String>();
		userandkey=new HashMap<String, SecretKeySpec>();
		timestamps=new HashMap<String, String>();
		ipanduser=new HashMap<String, String>();
		loginuers=new HashMap<String, String>();
		banedusers=new HashMap<String, String>();
		userandport=new HashMap<String, Integer>();
		ExecutorService executorService=Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors()*100);
		int port=getport();
		try {
			server=new ServerSocket(port);
		} catch (Exception e) {
			System.out.println("the port is occupied, change the port and restart");
		}
		while(true) {
			try
			{
				Socket socket=server.accept();
				// get the user input message and use server private key to decrypt the message
				InputStream in = socket.getInputStream();
				DataInputStream inStream=new DataInputStream(in);
				String recmsg=inStream.readUTF();
				recmsg=rsa.rsadecrypt(recmsg);
				// if user sending login request
				if(recmsg.startsWith("login"))
				{
					executorService.execute((new loginthread(socket,recmsg)));
				}
				// if user request current login users name list
				else 
				if(recmsg.startsWith("list"))
				{
					executorService.execute((new listthread(socket,recmsg)));
				}
				else
				// if user request to send message to a current login user
				if(recmsg.startsWith("send"))
				{
					executorService.execute((new visittargetthread(socket,recmsg)));
				}
				else
				// if user request to log off
				if(recmsg.startsWith("logoff"))
				{
					executorService.execute((new logoffthread(socket,recmsg)));
				}
				else {
					System.out.println("bad request");
				}
			}catch (IOException e) {
				System.out.println("there is something wrong with client");
				loginuers.remove(clientusername);
				syncookies.remove(clientusername);
				userandip.remove(clientusername);
				timestamps.remove(clientusername);
				userandkey.remove(clientusername);
				userandport.remove(clientusername);
		} 
		} 
	}
	// get the server port to run the server
	private static int getport() {
		try {
			FileReader reader=new FileReader("d:/serverport.txt");
			BufferedReader bf=new BufferedReader(reader);
			String temp;
			temp=bf.readLine();
			bf.close();
			reader.close();
			return Integer.parseInt(temp);
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return 0;
	}
}

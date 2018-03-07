import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Random;
import java.util.Scanner;

/**
 * Tan Shi Terng Leon
 * 4000602
 * Client.java
 * Description: A client program to communicate with a host
 */

/**
 * @author User
 *
 */
public class Client {

	/**
	 * @param args
	 */
	private static final String DEFAULTNAME = "Bob", DEFAULTIP = "127.0.0.1";
	private static final int KEYSIZE = 128, DEFAULTMSGSIZE = 2048, DEFAULTPORT = 5555;
	public static String name, hostName;
	private static BigInteger p, g, myPubKey, x, herPubKey, sessionKey;
	private static byte[] ctext;
	private static RC4 rc4;
	private static int port;
	
	public static void main(String[] args) {
		try {
			DatagramSocket socket = new DatagramSocket();
			DatagramPacket packet = new DatagramPacket(new byte[DEFAULTMSGSIZE], DEFAULTMSGSIZE);
			
			InetAddress iaddr = InetAddress.getByName(DEFAULTIP);
			name = DEFAULTNAME;
			port = DEFAULTPORT;
			
			String msg = new String();
			String para[];
			
			if (args.length == 1)
				name = args[0];
			else if (args.length == 2) {
				name = args[0];
				iaddr = InetAddress.getByName(args[1]);
			}
			else if (args.length == 3) {
				name = args[0];
				iaddr = InetAddress.getByName(args[1]);
				port = Integer.parseInt(args[2]);
			}
			
			System.out.println(name + " " + InetAddress.getLocalHost());
			
			//Sending connection request
			msg = "Connect " + name;
			packet = new DatagramPacket(msg.getBytes(), msg.length(), iaddr, port);
			socket.send(packet);
			
			//Receiving public key
			packet = new DatagramPacket(new byte[DEFAULTMSGSIZE], DEFAULTMSGSIZE);
			socket.receive(packet);
			msg = new String(packet.getData(), 0, packet.getLength());
			
			if (msg.equals("NAME_IN_USE")) {
				extracted();
			}
			
			para = msg.split(":");
			p = new BigInteger(para[0]);
			g = new BigInteger(para[1]);
			herPubKey = new BigInteger(para[2]);
			hostName = para[3];
			
			//Calculate keys
			generateKeys();
			rc4 = new RC4(sessionKey);
			
			//Send this client's public key over with an encrypted message
			StringBuffer sb = new StringBuffer(myPubKey.toString());
			msg = new String(rc4.crypt("Hello".getBytes()));
			sb.append(" ").append(msg);
			packet.setData(sb.toString().getBytes());
			socket.send(packet);
			
			//Receive acknowledgement
			packet = new DatagramPacket(new byte[DEFAULTMSGSIZE], DEFAULTMSGSIZE);
			socket.receive(packet);
			msg = new String(rc4.crypt(packet.getData()), 0, packet.getLength());
			System.out.println(hostName + ">" + msg);
			
			System.out.println("Connection established with " + hostName + " " + packet.getAddress());
			
			//Receiving thread (full duplex communication)
			Thread t1 = new Thread(new Display(socket, rc4));
			t1.start();
			
			Scanner sc = new Scanner(System.in);
			
			while (!msg.equals("exit")) {
				msg = sc.nextLine();
				ctext = rc4.crypt(msg.getBytes());
				//packet = //new DatagramPacket(ctext, ctext.length, iaddr, 5555);
				packet.setData(ctext);
				try {
					socket.send(packet);
				} catch (IOException e) {
					e.printStackTrace();
					sc.close();
				}
			}
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (Exception e1) {
			//e1.printStackTrace();
			System.out.println(e1.getMessage());
		}
	}

	private static void extracted() throws Exception {
		throw new Exception("Username " + name + " already in use");
	}
	
	static public void generateKeys() {
		//Generate secret key
		Random rand = new Random();
		x = new BigInteger(KEYSIZE, rand).mod(p);
		
		//Compute public key
		myPubKey = g.modPow(x, p);
		
		//Compute the Diffie-Hellman key
		sessionKey = herPubKey.modPow(x, p);
	}
}

class RC4 {
	private byte[] S;
	byte[] key;
	
	public RC4(BigInteger sKey) {
		key = sKey.toByteArray();
	}
	
	public RC4(String sKey) {
		key = sKey.getBytes();
	}
	
	private void initialize() {
		S = new byte[256];
		for (int i = 0; i < 256; i++) {
			S[i] = (byte) i;
		}
	}
	
	private void ksa() {
		byte temp;
		int j = 0;
		for (int i = 0; i < 256; i++) {
			j = (j + (S[i] & 0xFF) + (key[i % key.length] & 0xFF)) % 256;
			
			//Swap
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
		}
	}
	
	private byte[] prng(int msglen) {
		byte [] keystream = new byte[msglen];
		byte temp;
		int i = 0, j = 0, k;
		
		for (k = 0; k < msglen; k++) {
			i = (i + 1) % 256;
			j = (j + (S[i] & 0xFF)) % 256;
			
			//Swap
			temp = S[i];
			S[i] = S[j];
			S[j] = temp;
			
			keystream[k] = S[((S[i] & 0xFF) + (S[j] & 0xFF)) % 256];
		}
		
		return keystream;
	}
	
	public byte[] crypt(byte [] input) {
		byte[] output = new byte[input.length];
		
		initialize();
		ksa();
		
		byte[] keystream = prng(input.length);
		
		for (int i = 0; i < input.length; i++) {
			output[i] = (byte) (input[i] ^ keystream[i]);
		}
		
		return output;
	}
}

class Display implements Runnable {	//Display thread
	
	DatagramSocket socket;
	DatagramPacket packet;
	RC4 rc4;
	byte[] ctext;
	String msg;
	
	public Display(DatagramSocket s, RC4 encryption) {
		socket = s;
		rc4 = encryption;
	}
	@Override
	public void run() {
		while (true) {
			packet = new DatagramPacket(new byte[2048], 2048);
			try {
				socket.receive(packet);
				ctext = rc4.crypt(packet.getData());
				msg = new String(ctext, 0, packet.getLength());
				
				if (msg.equals("EXITOK")) {	//If client is closing connection
					System.out.println("You have left the conversation");
					System.exit(0);
				}
				else if (msg.equals("SERVERCLOSED")) {	//If server is closing connection
					System.out.println(Client.hostName + " has closed the connection");
					System.exit(0);
				}
				else	//Prints server message
					System.out.println(Client.hostName + ">" + msg);
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
}

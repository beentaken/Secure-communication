import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Scanner;
import java.util.Vector;

/**
 * Tan Shi Terng Leon
 * 4000602
 * Host.java
 * Description: A host server for communicating with clients
 */

/**
 * @author User
 *
 */
public class Host {

	/**
	 * @param args
	 */
	public static final int DEFAULTSIZE = 2048;
	public static final int DEFAULTPORT = 5555;
	private static BigInteger p, g, x, myPublicKey, otherPublicKey, sessionKey;
	private static byte[] ctext;
	private static ClientInfo client;
	private static String name = "Alice";
	public static Vector<ClientInfo> currSess = new Vector<ClientInfo>();
	private static DatagramSocket socket;
	private static DatagramPacket packet;
	private static int idx;
	private static int port = DEFAULTPORT;
	
	public static void main(String[] args) {
		if (args.length == 1)
			name = args[0];
		else if (args.length == 2) {
			name = args[0];
			port = Integer.parseInt(args[1]);
		}
		
		getKey();
		
		try {
			socket = new DatagramSocket(port);	//Bind the socket to a port
			String msg = new String();
			String clientName = null;
			System.out.println(name + " " + InetAddress.getLocalHost() + " " + socket.getLocalPort());
			
			//Thread to get input from Host
			//provides full duplex communication
			Thread inputThread = new Thread(new Input(socket));
			inputThread.start();
			
			while (true) {
				try {
					packet = new DatagramPacket(new byte[DEFAULTSIZE], DEFAULTSIZE);
					socket.receive(packet);
					
					if ((idx = getClientIdx(packet)) >= 0) {	//Session already established
						ctext = packet.getData();
						
						//Decrypts the message
						msg = new String(currSess.get(idx).rc4.crypt(ctext), 0, packet.getLength());
						
						if (msg.equals("exit")) {	//If clients request to exit
							//Acknowledge disconnection
							packet.setData(currSess.get(idx).rc4.crypt("EXITOK".getBytes()));
							socket.send(packet);
							System.out.println(currSess.get(idx).name + " has logged off");
							
							//Remove the current session
							for (int i = 0; i < currSess.size(); i++) {
								if (currSess.get(i).packet.getAddress().equals(packet.getAddress()))
									currSess.remove(i);
							}
						}
						else	//Prints message to screen
							System.out.println(currSess.get(idx).name + ">" + msg);
					}
					else {
						msg = new String(packet.getData(), 0, packet.getLength());
						String [] para = msg.split(" ");
						
						if (para[0].equals("Connect")) {	//If it is a connection request
							clientName = para[1];
							
							if (getClientByName(clientName) >= 0) {	//If client name already in use
								msg = "NAME_IN_USE";
								packet.setData(msg.getBytes());
								throw new Exception();
							}
							
							System.out.println(clientName + " wants to talk");
							
							//Sending public key and parameters
							StringBuffer sb = new StringBuffer();
							sb.append(p).append(":").append(g).append(":").append(myPublicKey);
							sb.append(":").append(name);
							msg = sb.toString();
							packet.setData(msg.getBytes());
							socket.send(packet);
							
							//Receive ephemeral public key and and encrypted message
							packet = new DatagramPacket(new byte[2048], 2048);
							socket.receive(packet);
							msg = new String(packet.getData(), 0, packet.getLength());
							para = msg.split(" ");
							otherPublicKey = new BigInteger(para[0]);
							sessionKey = otherPublicKey.modPow(x, p);
							
							//Decrypts message and send back
							RC4 rc4 = new RC4(sessionKey);
							msg = new String(rc4.crypt(para[1].getBytes()));
							System.out.println(clientName + ">" + msg);
							msg = "Received " + msg;
							packet.setData(rc4.crypt(msg.getBytes()));
							socket.send(packet);
							
							//Adds the new session to the list of current session
							client = new ClientInfo(clientName, packet, rc4);
							currSess.add(client);
						}
						System.out.println("Connection established with " + client.name
								+ " " + client.packet.getAddress());
					}
				} catch (IOException e) {
					e.printStackTrace();
					socket.close();
				} catch (Exception e) {
				}
			}
		} catch (SocketException e) {
			e.printStackTrace();
		} catch (UnknownHostException e1) {
			e1.printStackTrace();
		}
	}
	
	//Get the client/session by its IP address
	private static int getClientIdx(DatagramPacket packet) {
		if (currSess.isEmpty())
			return -1;
		
		for (int i = 0; i < currSess.size(); i++) {
			if (currSess.get(i).packet.getAddress().equals(packet.getAddress()))
				return i;
		}
		return -1;
	}
	
	//Get the client/session by the name
	public static int getClientByName(String name) {
		if (currSess.isEmpty())
			return -1;
		
		for (int i = 0; i < currSess.size(); i++) {
			if (currSess.get(i).name.equals(name))
				return i;
		}
		return -1;
	}
	
	//Display all current clients/sessions
	public static void displayClients() {
		if (currSess.isEmpty())
			System.out.println("No available clients");
		else {
			for (int i = 0; i < currSess.size(); i++) {
				System.out.println(currSess.get(i).name + " " + currSess.get(i).packet.getAddress());
			}
		}
	}
	
	//Reads the private and public keys and the parameters from a file
	public static void getKey() {
		try {
			Scanner sc = new Scanner(new File("key.txt"));
			String input;
			if (sc.hasNextLine()) {
				input = sc.nextLine();
				p = new BigInteger(input);
			}
			if (sc.hasNextLine()) {
				input = sc.nextLine();
				g = new BigInteger(input);
			}
			if (sc.hasNextLine()) {
				input = sc.nextLine();
				x = new BigInteger(input);	//Secret key
			}
			if (sc.hasNextLine()) {
				input = sc.nextLine();
				myPublicKey = new BigInteger(input);
			}
			sc.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
	}

}

class ClientInfo {	//Stores info one a client session
	public String name;			//Client name
	public DatagramPacket packet;	//Stores client IP address
	public RC4 rc4;				//Encryption or decryption
	
	public ClientInfo (String n, DatagramPacket p, RC4 encryption) {
		name = n;
		packet = p;
		rc4 = encryption;
	}
}

class Input implements Runnable {	//Thread to receive input from user (Alice)
	private DatagramSocket socket;
	private DatagramPacket packet;
	private byte[] ctext;
	private int currIdx;
	private String currClientName = new String();
	
	public Input(DatagramSocket s) {
		socket = s;
	}
	
	@Override
	public void run() {
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String msg;
		int idx;
		
		while (true) {
			try {
				msg = br.readLine();
				
				if (msg.equals(""))
					msg = "\n";
			
			if (msg.charAt(0) == '/') {	//Options
				if (msg.charAt(1) == 's') {		//Switch client session
					String name = msg.substring(2).trim();
					
					if ((idx = Host.getClientByName(name)) >= 0) {	//If session exists
						packet = new DatagramPacket(new byte[Host.DEFAULTSIZE], Host.DEFAULTSIZE);
						//Use the packet containing that address
						packet = Host.currSess.get(idx).packet;
						System.out.println("You are now talking to " + " " + Host.currSess.get(idx).name +
								" " + Host.currSess.get(idx).packet.getAddress());
						currClientName = name;
					}
					else
						System.out.println("Client not found");
				}
				else if (msg.charAt(1) == 'l')	//List all current sessions
					Host.displayClients();
				else if (msg.charAt(1) == 'c') {	//Close a connection with a client
					String name = msg.substring(2).trim();	//Client name
					
					if ((idx = Host.getClientByName(name)) >= 0) {	//If session exists
						//Use the packet containing that address
						DatagramPacket cpacket = Host.currSess.get(idx).packet;
						msg = "SERVERCLOSED";
						ctext = Host.currSess.get(idx).rc4.crypt(msg.getBytes());
						cpacket.setData(ctext);
						socket.send(cpacket);
						System.out.println("Closed connection with " + Host.currSess.get(idx).name + " "
								+ Host.currSess.get(idx).packet.getAddress());
						
						//Remove the session
						for (int i = 0; i < Host.currSess.size(); i++) {
							if (Host.currSess.get(i).packet.getAddress().equals(cpacket.getAddress()))
								Host.currSess.remove(i);
						}
					}
					else
						System.out.println("Client not found");
				}
				else if (msg.substring(1).equals("exit")) {	//Closes all connections and exit program
					for (int i = 0; i < Host.currSess.size(); i++) {
						packet = Host.currSess.get(i).packet;
						msg = "SERVERCLOSED";
						ctext = Host.currSess.get(i).rc4.crypt(msg.getBytes());
						packet.setData(ctext);
						socket.send(packet);
					}
					System.out.println("Server closed");
					System.exit(0);
				}
				else
					System.out.println("Invalid option");
			}
			else {	//Normal
				currIdx = Host.getClientByName(currClientName);
				if (currIdx != -1) {	//If session exists
					//Encrypts the message
					ctext = Host.currSess.get(currIdx).rc4.crypt(msg.getBytes());
					//Gets the corresponding packet
					packet = Host.currSess.get(currIdx).packet;
					packet.setData(ctext);	//Put the encrypted message into the packet
					try {
						socket.send(packet);	//Sends the packet
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				else if (Host.currSess.isEmpty()) {	//If no current sessions
					System.out.println("No one to talk to :(");
				}
				else {	//If the current session no longer exists
					if (!currClientName.isEmpty())
						System.out.println(currClientName +
								" not found. Please select a person to talk to by typing '/s<client name>'");
					else	//First time use (currClientName is empty)
						System.out.println("Please select a person to talk to by typing '/s<client name>'");
				}
			}
			} catch (IOException e1) {
				e1.printStackTrace();
			}

		}
	}
	
}

class RC4 {
	private byte[] S;
	private byte[] key;
	
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
	
	private void ksa() {	//Key scheduling algorithm
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
	
	private byte[] prng(int msglen) {	//Pseudo-random number generator
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
	
	public byte[] crypt(byte [] input) {	//Encrypt or decrypt
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
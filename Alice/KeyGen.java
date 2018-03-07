import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

/**
 * Tan Shi Terng Leon
 * 4000602
 * KeyGen.java
 * Description: Generates the public and private keys and parameters for the host
 */

/**
 * @author User
 *
 */
public class KeyGen {

	/**
	 * @param args
	 */
	private static final int KEYSIZE = 128;
	private static final String DEFAULTFILENAME = "key.txt";
	private static BigInteger p, g, x, y;
	private static Random rand;
	private static String fileName;
	
	public static void main(String[] args) {
		fileName = DEFAULTFILENAME;
		if (args.length == 1)
			fileName = args[0];
		
		rand = new Random();;
		
		//Computes a safe prime for p
		System.out.print("Generating p.....");
		do {
			p = BigInteger.probablePrime(KEYSIZE, rand);
		} while (!isSafePrime(p));
		System.out.println("done");
		
		//Computes the generator g
		System.out.print("Generating g.....");
		getGenerator();
		System.out.println("done");
		
		//Private key
		System.out.print("Generating x.....");
		x = new BigInteger(KEYSIZE, rand).mod(p);
		System.out.println("done");
		
		//Public key
		System.out.print("Generating y.....");
		y = g.modPow(x, p);
		System.out.println("done");
		
		//Write to file
		System.out.println("Writing to file.....");
		try {
			FileWriter fw = new FileWriter(new File(fileName));
			fw.write(p + "\n" + g + '\n' + x + '\n' + y + '\n');
			fw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		
		System.out.println("Keys generated successfully and stored in " + fileName);
	}
	
	//Checks if g is a safe prime
	public static boolean isSafePrime(BigInteger g) {
		boolean isSafe = false;
		BigInteger temp = g.subtract(new BigInteger("1")).divide(new BigInteger("2"));
		if (temp.isProbablePrime(80))
			isSafe = true;
		
		return isSafe;
	}
	
	//Computes a generator
	public static void getGenerator() {
		g = new BigInteger(KEYSIZE, rand).mod(p);
		
		BigInteger power = p.subtract(new BigInteger("1")).divide(new BigInteger("2"));
		
		//Computing g^((p-1)/2) mod p
		BigInteger testValue = g.modPow(power, p);
		
		//Checks if g^((p-1)/2) mod p is equal to 1
		if (testValue.compareTo(new BigInteger("1")) == 0)	//If g is not a generator
			g = g.negate().mod(p);	//(-g) mod p is a generator
	}
}

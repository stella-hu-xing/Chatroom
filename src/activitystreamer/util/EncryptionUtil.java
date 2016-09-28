package activitystreamer.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class EncryptionUtil {

	public static KeyPair generateKey() {
		try {
			final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair key = keyGen.generateKeyPair();

			return key;

		} catch (Exception e) {
			e.printStackTrace();
		}
		KeyPair keyNull = null;
		return keyNull;

	}

	// public static String encyrpt(String text, PublicKey key) {
	// String cipherText = null;
	// try {
	// Cipher cipher = Cipher.getInstance(ALGORITHM);
	// cipher.init(Cipher.ENCRYPT_MODE, key);
	// byte[] plainTxtBytes = text.getBytes("UTF-8");
	// // byte[] encBytes = cipher.doFinal(plainTxtBytes);
	// // cipherText = new sun.misc.BASE64Encoder().encode(encBytes);
	//
	// byte[] encrypted = blockCipher(plainTxtBytes, Cipher.ENCRYPT_MODE);
	// char[] encryptedTranspherable = Hex.encodeHex(encrypted);
	// return new String(encryptedTranspherable);
	// // byte[] a = text.getBytes();
	// // byte[] b = cipher.doFinal(a);
	// // cipherText = DatatypeConverter.printBase64Binary(b);
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	// return cipherText;
	// }

	// public static String decyrpt(String text, PrivateKey key) {
	// String decyrptText = null;
	// try {
	// final Cipher cipher = Cipher.getInstance(ALGORITHM);
	// cipher.init(Cipher.DECRYPT_MODE, key);
	// // byte[] encBytes = new
	// // sun.misc.BASE64Decoder().decodeBuffer(text);
	// // byte[] plainTxtBytes = cipher.doFinal(encBytes);
	// // decyrptText = new String(plainTxtBytes);
	//
	// byte[] a = DatatypeConverter.parseBase64Binary(text);
	// byte[] b = cipher.doFinal(a);
	// decyrptText = new String(b);
	//
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	// return decyrptText;
	// }

	public static String encyrpt(String text, PublicKey key) {
		String cipherText = null;
		try {
			// Cipher cipher = Cipher.getInstance(ALGORITHM);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] bytes = text.getBytes("UTF-8");

			byte[] encrypted = blockCipher(bytes, Cipher.ENCRYPT_MODE, cipher);

			// char[] encryptedTranspherable = Hex.encodeHex(encrypted);
			cipherText = DatatypeConverter.printBase64Binary(encrypted);

		} catch (Exception e) {
			e.printStackTrace();
		}
		return cipherText;
	}

	public static String decyrpt(String text, PrivateKey key) {
		String decrypText = null;
		try {
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] convers = DatatypeConverter.parseBase64Binary(text);

			byte[] decrypted = blockCipher(convers, Cipher.DECRYPT_MODE, cipher);

			decrypText = new String(decrypted, "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return decrypText;
	}

	private static byte[] blockCipher(byte[] bytes, int mode, Cipher cipher)
			throws IllegalBlockSizeException, BadPaddingException {

		byte[] scrambled = new byte[0];

		byte[] toReturn = new byte[0];
		int length = (mode == Cipher.ENCRYPT_MODE) ? 100 : 128;

		byte[] buffer = new byte[length];

		for (int i = 0; i < bytes.length; i++) {

			if ((i > 0) && (i % length == 0)) {
				scrambled = cipher.doFinal(buffer);
				toReturn = append(toReturn, scrambled);
				int newlength = length;

				if (i + length > bytes.length) {
					newlength = bytes.length - i;
				}
				buffer = new byte[newlength];
			}
			buffer[i % length] = bytes[i];
		}

		scrambled = cipher.doFinal(buffer);

		toReturn = append(toReturn, scrambled);

		return toReturn;
	}

	private static byte[] append(byte[] prefix, byte[] suffix) {
		byte[] toReturn = new byte[prefix.length + suffix.length];
		for (int i = 0; i < prefix.length; i++) {
			toReturn[i] = prefix[i];
		}
		for (int i = 0; i < suffix.length; i++) {
			toReturn[i + prefix.length] = suffix[i];
		}
		return toReturn;
	}
}
package org.twinecoin.test.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA256 {

	private final static ThreadLocal<MessageDigest> localMD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			try {
				return MessageDigest.getInstance("SHA-256", "BC");
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				// This should not happen
				return null;
			}
		}
	};

	/**
	 * Gets a SHA256 message digest object
	 * 
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getMessageDigest() {
		return localMD.get();
	}

}

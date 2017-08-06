package org.twinecoin.test.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256 {

	private final static ThreadLocal<MessageDigest> localMD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			try {
				return MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				// This should not be possible
				return null;
			}
		}
	};

	public static MessageDigest getMessageDigest() {
		return localMD.get();
	}

}

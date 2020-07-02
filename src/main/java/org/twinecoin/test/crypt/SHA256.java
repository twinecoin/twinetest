package org.twinecoin.test.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA256 {

	private final static ThreadLocal<MessageDigest> localSHA256MD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			return createSHA256MessageDigest();
		}
	};

	private final static ThreadLocal<MessageDigest> localDSHA256MD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			return createDSHA256MessageDigest();
		}
	};

	private static MessageDigest createSHA256MessageDigest() {
		try {
			return MessageDigest.getInstance("SHA-256", "BC");
		} catch (NoSuchAlgorithmException e) {
			// This should not happen
		} catch (NoSuchProviderException e) {
			// This should not happen
		}
		return null;
	}

	private static MessageDigest createDSHA256MessageDigest() {
		MessageDigest inner = getSHA256MessageDigest();
		if (inner == null) {
			return null;
		}
		return new DoubleMessageDigest(inner);
	}

	/**
	 * Gets a thread local SHA256 message digest object.  It must be discarded
	 * after use.
	 * 
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getSHA256MessageDigest() {
		return localSHA256MD.get();
	}

	/**
	 * Gets a thread local DSHA256 (double SHA256) message digest object.  It 
	 * must be discarded after use.
	 * 
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getDSHA256MessageDigest() {
		return localDSHA256MD.get();
	}

}

package org.twinecoin.test.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class SHA512 {

	private final static ThreadLocal<MessageDigest> localSHA512MD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			return createSHA512MessageDigest();
		}
	};

	private final static ThreadLocal<MessageDigest> localDSHA512MD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			return createDSHA512MessageDigest();
		}
	};

	private static MessageDigest createSHA512MessageDigest() {
		try {
			return MessageDigest.getInstance("SHA-512", "BC");
		} catch (NoSuchAlgorithmException e) {
			// This should not happen
		} catch (NoSuchProviderException e) {
			// This should not happen
		}
		return null;
	}

	private static MessageDigest createDSHA512MessageDigest() {
		MessageDigest inner = getSHA512MessageDigest();
		if (inner == null) {
			return null;
		}
		return new DoubleMessageDigest(inner);
	}

	/**
	 * Gets a thread local SHA512 message digest object.  It must be discarded
	 * after use.
	 * 
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getSHA512MessageDigest() {
		return localSHA512MD.get();
	}

	/**
	 * Gets a thread local DSHA512 (double SHA512) message digest object.  It 
	 * must be discarded after use.
	 * 
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getDSHA512MessageDigest() {
		return localDSHA512MD.get();
	}

}

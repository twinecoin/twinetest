package org.twinecoin.test.crypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class RIPEMD160 {

	private final static ThreadLocal<MessageDigest> localRIPEMD160MD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			return createRIPEMD160MessageDigest();
		}
	};

	private final static ThreadLocal<MessageDigest> localDRIPEMD160MD = new ThreadLocal<MessageDigest>() {
		protected MessageDigest initialValue() {
			return createDRIPEMD160MessageDigest();
		}
	};

	private static MessageDigest createRIPEMD160MessageDigest() {
		try {
			return MessageDigest.getInstance("RIPEMD160", "BC");
		} catch (NoSuchAlgorithmException e) {
			// This should not happen
		} catch (NoSuchProviderException e) {
			// This should not happen
		}
		return null;
	}

	private static MessageDigest createDRIPEMD160MessageDigest() {
		MessageDigest inner = getRIPEMD160MessageDigest();
		if (inner == null) {
			return null;
		}
		return new DoubleMessageDigest(inner);
	}

	/**
	 * Gets a thread local RIPEMD160 message digest object.  It must be discarded
	 * after use.
	 *
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getRIPEMD160MessageDigest() {
		return localRIPEMD160MD.get();
	}

	/**
	 * Gets a thread local DRIPEMD160 (double RIPEMD160) message digest object.  It
	 * must be discarded after use.
	 *
	 * @return the message digest or null on failure
	 */
	public static MessageDigest getDRIPEMD160MessageDigest() {
		return localDRIPEMD160MD.get();
	}

}

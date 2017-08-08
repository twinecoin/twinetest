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
		DSHA256MessageDigest md = new DSHA256MessageDigest();
		if (!md.isNull()) {
			return md;
		}
		return null;
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

	private static class DSHA256MessageDigest extends MessageDigest {
		private final MessageDigest SHA256md;

		protected DSHA256MessageDigest() {
			super("DSHA256");
			SHA256md = getSHA256MessageDigest();
		}

		public boolean isNull() {
			return SHA256md == null;
		}

		@Override
		protected void engineUpdate(byte input) {
			SHA256md.update(input);
		}

		@Override
		protected void engineUpdate(byte[] input, int offset, int len) {
			SHA256md.update(input, offset, len);
		}

		@Override
		protected byte[] engineDigest() {
			byte[] hash1 = SHA256md.digest();
			SHA256md.reset();
			SHA256md.update(hash1);
			return SHA256md.digest();
		}

		@Override
		protected void engineReset() {
			SHA256md.reset();
		}
	}
}

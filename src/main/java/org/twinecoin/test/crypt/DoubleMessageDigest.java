package org.twinecoin.test.crypt;

import java.security.MessageDigest;

public class DoubleMessageDigest extends MessageDigest {
	private final MessageDigest md;

	protected DoubleMessageDigest(MessageDigest md) {
		super("D" + md.getAlgorithm());
		this.md = md;
	}

	public boolean isNull() {
		return md == null;
	}

	@Override
	protected void engineUpdate(byte input) {
		md.update(input);
	}

	@Override
	protected void engineUpdate(byte[] input, int offset, int len) {
		md.update(input, offset, len);
	}

	@Override
	protected byte[] engineDigest() {
		byte[] hash1 = md.digest();
		md.reset();
		md.update(hash1);
		return md.digest();
	}

	@Override
	protected void engineReset() {
		md.reset();
	}
}

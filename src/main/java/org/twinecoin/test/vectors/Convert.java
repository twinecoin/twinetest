package org.twinecoin.test.vectors;

import java.math.BigInteger;

public class Convert {
	public static String bigIntegerToU256(BigInteger value) {
		BigInteger mask = BigInteger.valueOf(0x00000000FFFFFFFFL);

		StringBuilder buf = new StringBuilder();
		buf.append("{");
		for (int i = 256 - 32; i >= 0; i -= 32) {
			if (i < 256 - 32) {
				buf.append(", ");
			}
			long word = value.shiftRight(i).and(mask).longValue();
			buf.append(String.format("0x%08x", word));
		}
		buf.append("}");
		return buf.toString();
	}

	public static BigInteger intToBigInteger(int[] value) {
		byte[] bytes = new byte[1 + value.length * 4];
		bytes[0] = 0;
		for (int i = 0; i < value.length; i++) {
			int b = (i << 2) + 1;
			bytes[b + 0] = (byte) (value[i] >> 24);
			bytes[b + 1] = (byte) (value[i] >> 16);
			bytes[b + 2] = (byte) (value[i] >> 8);
			bytes[b + 3] = (byte) (value[i] >> 0);
		}
		return new BigInteger(bytes);
	}

	public static String bytesToH256(byte[] hash) {
		StringBuilder buf = new StringBuilder();
		buf.append("{");
		for (int i = 0; i < 32; i++) {
			if (i > 0) {
				buf.append(", ");
			}
			buf.append(String.format("0x%02x", hash[i] & 0xFF));
		}
		buf.append("}");
		return buf.toString();
	}

	public static String bytesToU8(byte[] message, boolean forceHex) {
		boolean hasInvalid = false;
		for (byte m : message) {
			int b = m & 0xFF;
			if (forceHex || b < 32 || b > 127 || b == '"' || b == '\'' || b == '\\') {
				hasInvalid = true;
				break;
			}
		}
		StringBuilder sb = new StringBuilder(message.length * 4 + 2);
		sb.append('"');
		for (int i = 0; i < message.length; i++) {
			int b = message[i] & 0xFF;
			if (hasInvalid || b < 32 || b > 127 || b == '"' || b == '\'' || b == '\\') {
				sb.append("\\x");
				sb.append(String.format("%02x", message[i]));
			} else {
				sb.append((char) b);
			}
		}
		sb.append('"');
		return sb.toString();
	}

	public static BigInteger asn1toS(byte[] asn1) {
		if (asn1.length < 64) {
			System.out.println("To short");
			return null;
		}
		if (asn1[0] != 0x30) {
			System.out.println("Bad first char");
			return null;
		}
		if (asn1[1] != asn1.length - 2) {
			System.out.println("Bad first length");
			return null;
		}
		if (asn1[2] != 0x02) {
			System.out.println("Bad first int code");
			return null;
		}
		if (asn1[3] < 0 || asn1[3] > 0x21) {
			System.out.println("Bad first int len, " + asn1[3]);
			return null;
		}
		int sStart = 4 + asn1[3];
		if (asn1[sStart] != 0x02) {
			System.out.println("Bad second int code");
			return null;
		}
		int sLen = asn1[sStart + 1];
		if (sLen < 0 || sLen > 0x21) {
			System.out.println("Bad second int len");
			return null;
		}
		if (sStart + 2 + sLen != asn1.length) {
			System.out.println("Bad total len");
			return null;
		}
		byte[] sBigEndian = new byte[sLen];
		System.arraycopy(asn1, sStart + 2, sBigEndian, 0, sLen);
		return new BigInteger(sBigEndian);
	}
}

package org.twinecoin.test.vectors;

import java.math.BigInteger;

public class Convert {
	private static char[] hexChars = new char[] {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

	private static String[] hexBytes;

	static {
		hexBytes = new String[256];
		for (int i = 0; i < 256; i++) {
			hexBytes[i] = new String(new char[] {hexChars[i >> 4], hexChars[i & 0xF]});
		}
	}

	public static String getHex(int b) {
		return hexBytes[b & 0xFF];
	}

	public static String bigIntegerToU512Strict(BigInteger value, boolean strict) {
		if (value.compareTo(BigInteger.ONE.shiftLeft(512)) > 0) {
			throw new IllegalArgumentException("BigInteger out of range for U512, " + value.toString(16));
		}
		return bigIntegerToU512(value);
	}

	public static String bigIntegerToU512(BigInteger value) {
		BigInteger mask = BigInteger.ONE.shiftLeft(32).subtract(BigInteger.ONE);

		StringBuilder buf = new StringBuilder();
		buf.append("{");
		for (int i = 0; i < 512; i += 64) {
			if (i > 0) {
				buf.append(", ");
			}
			long halfWord = value.shiftRight(i + 32).and(mask).longValue();
			buf.append(String.format("0x%08x", halfWord));
			halfWord = value.shiftRight(i).and(mask).longValue();
			buf.append(String.format("%08xULL", halfWord));
		}
		buf.append("}");
		return buf.toString();
	}

	public static BigInteger LEBytesToBigInteger(byte[] message) {
		byte[] bigEndian = new byte[message.length + 1];
		int j = message.length - 1;
		for (int i = 1; i <= message.length; i++) {
			bigEndian[i] = message[j--];
		}
		return new BigInteger(bigEndian);
	}

	public static String LEBytesToU512(byte[] message) {
		return bigIntegerToU512(LEBytesToBigInteger(message));
	}

	public static String toU64FloatString(BigInteger man, int w_exp, int b_exp) {
		if (man.compareTo(U512TestVectors.U64_MAX) > 0) {
			throw new IllegalArgumentException("Mantissa out of range, " + man);
		}
		return String.format("{0x%016xULL, 0x%08x, 0x%08x}", man, w_exp, b_exp);
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

	public static BigInteger longToBigInteger(long[] value) {
		byte[] bytes = new byte[1 + value.length * 8];
		bytes[0] = 0;
		for (int i = 0; i < value.length; i++) {
			int b = (i << 3) + 1;
			bytes[b + 0] = (byte) (value[i] >> 56);
			bytes[b + 1] = (byte) (value[i] >> 48);
			bytes[b + 2] = (byte) (value[i] >> 40);
			bytes[b + 3] = (byte) (value[i] >> 32);
			bytes[b + 4] = (byte) (value[i] >> 24);
			bytes[b + 5] = (byte) (value[i] >> 16);
			bytes[b + 6] = (byte) (value[i] >> 8);
			bytes[b + 7] = (byte) (value[i] >> 0);
		}
		return new BigInteger(bytes);
	}

	public static long twoIntsToLong(int a, int b) {
		long aLong = (long) a;
		long bLong = (long) b;
		long combined = (aLong << 32) | (bLong & 0xFFFFFFFFL);
		return combined;
	}

	public static String bytesToH256(byte[] hash) {
		StringBuilder buf = new StringBuilder();
		buf.append("{");
		for (int i = 0; i < 32; i++) {
			if (i > 0) {
				buf.append(", ");
			}
			buf.append(getHex(hash[i] & 0xFF));
		}
		buf.append("}");
		return buf.toString();
	}

	public static String bytesToU8(boolean forceHex, byte[] ... messages) {
		int length = 0;
		boolean hasInvalid = forceHex;
		outerLoop:
		for (byte[] message : messages) {
			length += message.length;
			if (hasInvalid) {
				continue;
			}
			for (byte m : message) {
				int b = m & 0xFF;
				if (b < 32 || b > 127 || b == '"' || b == '\'' || b == '\\') {
					hasInvalid = true;
					continue outerLoop;
				}
			}
		}
		StringBuilder sb = new StringBuilder(length * 4 + 2);
		sb.append('"');
		for (byte[] message : messages) {
			for (int i = 0; i < message.length; i++) {
				int b = message[i] & 0xFF;
				if (hasInvalid) {
					sb.append("\\x");
					sb.append(getHex(b));
				} else {
					sb.append((char) b);
				}
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

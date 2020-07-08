package org.twinecoin.test.crypt;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyAgreement;

public class Secp256k1 {

	private static final byte[] privatePrefix = hexDecode("3047020100301006072A8648CE3D020106052B8104000A0430302E0201010420");
	private static final byte[] privateSuffix = hexDecode("A00706052B8104000A");

	private static final int privateLength = privatePrefix.length + privateSuffix.length + 32;
	private static final int privateKeyStart = privatePrefix.length;
	private static final int privateSuffixStart = privatePrefix.length + 32;

	private static final byte[] publicCompressedPrefix = hexDecode("3036301006072a8648ce3d020106052b8104000a032200");
	private static final byte[] publicUncompressedPrefix = hexDecode("3056301006072a8648ce3d020106052b8104000a034200");

	private static final ECPublicKey publicKeyG;
	private static final BigInteger n;
	private static final BigInteger p;
	private static final byte[] testMessage = hexDecode("0123456789ABCDEFFEDBCA98765432100123456789ABCDEFFEDBCA9876543210");

	static {
		ECPublicKey publicKeyGLocal = null;
		BigInteger nLocal = null;
		BigInteger pLocal = null;

		ECPrivateKey g = getECPrivateKey(BigInteger.ONE);
		if (g != null) {
			BigInteger gX = g.getParams().getGenerator().getAffineX();
			BigInteger gY = g.getParams().getGenerator().getAffineY();
			publicKeyGLocal = getECPublicKey(gX, gY);
			if (publicKeyGLocal != null) {
				nLocal = publicKeyGLocal.getParams().getOrder();
				ECField field = publicKeyGLocal.getParams().getCurve().getField();
				if (field instanceof ECFieldFp) {
					pLocal = ((ECFieldFp) field).getP();
				}
			}
		}
		publicKeyG = publicKeyGLocal;
		n = nLocal;
		p = pLocal;
	}

	public static BigInteger getOrder() {
		return n;
	}

	public static BigInteger getP() {
		return p;
	}

	public static ECPrivateKey getECPrivateKey(BigInteger x) {
		if (x == null) {
			throw new NullPointerException("Private key may not be null");
		}
		if (x.compareTo(BigInteger.ONE) < 0) {
			throw new IllegalArgumentException("Private key may not be zero or negative");
		}
		if (n != null && x.compareTo(n) >= 0) {
			throw new IllegalArgumentException("Private key must be less than the order of the curve");
		}
		byte[] encoded = new byte[privateLength];

		System.arraycopy(privatePrefix, 0, encoded, 0, privatePrefix.length);
		System.arraycopy(privateSuffix, 0, encoded, privateSuffixStart, privateSuffix.length);

		copyBigIntegerToByteArray(encoded, x, privateKeyStart, 32);

		EncodedKeySpec spec = new PKCS8EncodedKeySpec(encoded);

		try {
			KeyFactory kf = KeyFactory.getInstance("EC", "BC");
			PrivateKey key = kf.generatePrivate(spec);
			return (ECPrivateKey) key;
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
		} catch (InvalidKeySpecException e) {
		} catch (ClassCastException e) {
		}

		return null;
	}

	public static byte[] sign(ECPrivateKey pri, byte[] message) {
		if (pri == null) {
			throw new NullPointerException("Private key may not be null");
		}
		if (message == null) {
			throw new NullPointerException("Message may not be null");
		}
		if (message.length != 32) {
			throw new IllegalArgumentException("Message must be 32 bytes");
		}
		try {
			Signature signer = Signature.getInstance("NONEwithECDSA", "BC");
			signer.initSign(pri);
			signer.update(message);
			return signer.sign();
		} catch (SignatureException e) {
		} catch (InvalidKeyException e) {
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
		}
		return null;
	}

	public static boolean verify(ECPublicKey pub, byte[] message, byte[] sig) {
		if (pub == null) {
			throw new NullPointerException("Public key may not be null");
		}
		if (sig == null) {
			throw new NullPointerException("Signature may not be null");
		}
		if (message == null) {
			throw new NullPointerException("Message may not be null");
		}
		if (message.length != 32) {
			throw new IllegalArgumentException("Message must be 32 bytes");
		}
		try {
			Signature verifier = Signature.getInstance("NONEwithECDSA", "BC");
			verifier.initVerify(pub);
			verifier.update(message);
			return verifier.verify(sig);
		} catch (SignatureException e) {
		} catch (InvalidKeyException e) {
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
		}
		return false;
	}

	public static ECPublicKey getECPublicKey(ECPrivateKey pri) {
		if (pri == null) {
			throw new NullPointerException("Private key may not be null");
		}

		// There is no ECPrivateKey.getPublicKey() method.
		// ECDH does point multiplication internally, so can be used
		// instead.  It returns the x coordinate of the public key.
		// Both of the corresponding y values are checked to determine
		// which one is correct.
		if (publicKeyG == null) {
			return null;
		}

		try {
			KeyAgreement ka = KeyAgreement.getInstance("ECDH");
			ka.init(pri);
			ka.doPhase(publicKeyG, true);
			byte[] encoded = ka.generateSecret();
			byte[] encoded2 = new byte[33];
			System.arraycopy(encoded, 0, encoded2, 1, 32);
			BigInteger x = new BigInteger(encoded2);

			byte[] sig = sign(pri, testMessage);
			if (sig == null) {
				return null;
			}
			ECPublicKey pub = getECPublicKey(x, false);
			if (pub != null) {
				if (verify(pub, testMessage, sig)) {
					return pub;
				}
			}
			pub = getECPublicKey(x, true);
			if (pub != null) {
				if (verify(pub, testMessage, sig)) {
					return pub;
				}
			}
		} catch (InvalidKeyException e) {
		} catch (IllegalStateException e) {
		} catch (NoSuchAlgorithmException e) {
		}
		return null;
	}

	public static ECPublicKey getECPublicKey(BigInteger x, BigInteger y) {
		if (x == null) {
			throw new NullPointerException("X coordinate may not be null");
		}
		if (y == null) {
			throw new NullPointerException("Y coordinate may not be null");
		}
		if (x.compareTo(BigInteger.ZERO) < 0 || (p != null && x.compareTo(p) >= 0)) {
			throw new IllegalArgumentException("X coordinate must be less than the prime modulus");
		}
		if (y.compareTo(BigInteger.ZERO) < 0 || (p != null && y.compareTo(p) >= 0)) {
			throw new IllegalArgumentException("Y coordinate must be less than the prime modulus");
		}
		byte[] encoded = new byte[publicUncompressedPrefix.length + 1 + 64];

		System.arraycopy(publicUncompressedPrefix, 0, encoded, 0, publicUncompressedPrefix.length);

		encoded[publicUncompressedPrefix.length] = 4;
		copyBigIntegerToByteArray(encoded, x, publicUncompressedPrefix.length + 1, 32);
		copyBigIntegerToByteArray(encoded, y, publicUncompressedPrefix.length + 1 + 32, 32);

		EncodedKeySpec spec = new X509EncodedKeySpec(encoded);

		try {
			KeyFactory kf = KeyFactory.getInstance("EC", "BC");
			PublicKey key = kf.generatePublic(spec);
			return (ECPublicKey) key;
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
		} catch (InvalidKeySpecException e) {
		} catch (ClassCastException e) {
		}
		return null;
	}

	public static ECPublicKey getECPublicKey(BigInteger x, boolean odd) {
		if (x == null) {
			throw new NullPointerException("X coordinate may not be null");
		}
		if (x.compareTo(BigInteger.ZERO) < 0 || (p != null && x.compareTo(p) >= 0)) {
			throw new IllegalArgumentException("X coordinate must be less than the prime modulus");
		}
		byte[] encoded = new byte[publicCompressedPrefix.length + 1 + 32];

		System.arraycopy(publicCompressedPrefix, 0, encoded, 0, publicCompressedPrefix.length);

		encoded[publicCompressedPrefix.length] = (byte) (odd ? 3 : 2);
		copyBigIntegerToByteArray(encoded, x, publicCompressedPrefix.length + 1, 32);

		EncodedKeySpec spec = new X509EncodedKeySpec(encoded);

		try {
			KeyFactory kf = KeyFactory.getInstance("EC", "BC");
			PublicKey key = kf.generatePublic(spec);
			return (ECPublicKey) key;
		} catch (NoSuchAlgorithmException e) {
		} catch (NoSuchProviderException e) {
		} catch (InvalidKeySpecException e) {
		} catch (ClassCastException e) {
		}
		return null;
	}

	public static byte[] encodeDER(ECPublicKey pub, boolean compressed) {
		byte[] encoded = new byte[compressed ? 33 : 65];

		BigInteger x = pub.getW().getAffineX();
		BigInteger y = pub.getW().getAffineY();

		if (compressed) {
			if (y.and(BigInteger.ONE).equals(BigInteger.ONE)) {
				encoded[0] = 0x03;
			} else {
				encoded[0] = 0x02;
			}
		} else {
			encoded[0] = 0x04;
		}

		copyBigIntegerToByteArray(encoded, x, 1, 32);

		if (!compressed) {
			copyBigIntegerToByteArray(encoded, y, 33, 32);
		}

		return encoded;
	}

	private static void copyBigIntegerToByteArray(byte[] buf, BigInteger i, int pos, int len) {
		byte[] integerBytes = i.toByteArray();

		int integerLength = Math.min(integerBytes.length, len);
		System.arraycopy(integerBytes, integerBytes.length - integerLength, buf, pos + len - integerLength, integerLength);
	}

	private static byte[] hexDecode(String hexString) {
		if ((hexString.length() & 1) != 0) {
			return null;
		}
		byte[] buf = new byte[hexString.length() >> 1];
		int j = 0;
		for (int i = 0; i < buf.length; i++) {
			buf[i] = (byte) ((hexCharToInt(hexString.charAt(j)) << 4) | hexCharToInt(hexString.charAt(j + 1)));
			j += 2;
		}
		return buf;
	}

	private static int hexCharToInt(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		} else if (c >= 'a' && c <= 'f') {
			return 10 + c - 'a';
		} else if (c >= 'A' && c <= 'F') {
			return 10 + c - 'A';
		}
		return -1;
	}
}

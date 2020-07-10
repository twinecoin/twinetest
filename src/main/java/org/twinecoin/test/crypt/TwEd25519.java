package org.twinecoin.test.crypt;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey;
import org.bouncycastle.util.encoders.Hex;

public class TwEd25519 {

	private final static ASN1Object privateKeyEncodeVersion = new ASN1Integer(1L);

	private final static ASN1ObjectIdentifier curveOID = new ASN1ObjectIdentifier("1.3.101.112");

	private final static ASN1Sequence curveIdentifierSequence = new DERSequence(new ASN1Encodable [] {curveOID});

	private static byte[] derEncode(byte[] seed) {
		if (seed.length != 32) {
			return null;
		}
		int length = seed[0] < 0 ? 35 : 34;

		byte[] encoded = new byte[length];

		System.arraycopy(seed, 0, encoded, length - 32, 32);

		encoded[0] = 0x04;
		encoded[1] = (byte) (length - 2);

		return encoded;
	}

	public static PrivateKey createPrivateKey(byte[] seed) {

		byte[] derEncoded = derEncode(seed);

		ASN1Object privateKey = new BEROctetString(derEncoded);

		ASN1Sequence privateKeySequence = new DERSequence(new ASN1Encodable [] {
				privateKeyEncodeVersion,
				curveIdentifierSequence,
				privateKey
		});

		PKCS8EncodedKeySpec keySpec;
		try {
			keySpec = new PKCS8EncodedKeySpec(privateKeySequence.getEncoded());
		} catch (IOException e) {
			return null;
		}

		KeyFactory ed25519KeyFactory;
		try {
			ed25519KeyFactory = KeyFactory.getInstance("Ed25519", "BC");
		} catch (NoSuchAlgorithmException e) {
			return null;
		} catch (NoSuchProviderException e) {
			return null;
		}

		try {
			return ed25519KeyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			return null;
		}
	}

	public static PublicKey getPublicKey(PrivateKey privateKey) {
		if (privateKey instanceof EdDSAPrivateKey) {
			return ((EdDSAPrivateKey) privateKey).getPublicKey();
		}
		return null;
	}

	public static byte[] getPublicKeyDERBytes(PublicKey publicKey) {
		byte[] asn1Encoded = publicKey.getEncoded();

		if (asn1Encoded.length < 4) {
			return null;
		}

		int topSequenceStart = 0;
		int topSequenceTag = asn1Encoded[topSequenceStart];
		int topSequenceLength = asn1Encoded[topSequenceStart + 1];

		if (topSequenceTag != 0x30) {
			return null;
		}

		if (topSequenceLength != asn1Encoded.length - 2) {
			return null;
		}

		int identifierSequenceStart = topSequenceStart + 2;
		int identifierSequenceTag = asn1Encoded[identifierSequenceStart];
		int identifierSequenceLength = asn1Encoded[identifierSequenceStart + 1];

		if (identifierSequenceTag != 0x30) {
			return null;
		}

		int keyBitStringStart = identifierSequenceStart + 2 + identifierSequenceLength;

		if (asn1Encoded.length < keyBitStringStart + 2) {
			return null;
		}

		int keyBitStringTag = asn1Encoded[keyBitStringStart];
		int keyBitStringLength = asn1Encoded[keyBitStringStart + 1];

		if (keyBitStringTag != 0x03) {
			return null;
		}

		if (keyBitStringLength < 32) {
			return null;
		}

		byte[] validEncoding = new byte[34];
		System.arraycopy(asn1Encoded, keyBitStringStart + 2 + keyBitStringLength - 32, validEncoding, 2, 32);

		validEncoding[0] = 0x03;
		validEncoding[1] = 0x20;

		return validEncoding;
	}
}
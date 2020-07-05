package org.twinecoin.test.vectors;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import org.twinecoin.test.crypt.RIPEMD160;
import org.twinecoin.test.crypt.SHA256;
import org.twinecoin.test.crypt.SHA512;

/**
 * Class to generate test vectors for the tw_sha256 class.<br>
 * <br>
 * This ensures that the test vectors are generated by a separate
 * implementation.
 */
public class HashTestVectors {

	public static List<String> generateVectors() {
		Random r = getRandom();

		List<String> lines = new ArrayList<String>();

		List<Integer> repeats = new ArrayList<Integer>();
		List<byte[]> messages = generateTestMessages(r, repeats);
		lines.addAll(generateSHA256Vectors(messages, repeats));

		return lines;
	}

	public static Random getRandom() {
		Random r = new Random();

		// Seed random so that results are consistent
		r.setSeed(0x280e788cff6ec2bbL);
		return r;
	}

	public static List<byte[]> generateTestMessages(Random r, List<Integer> repeats) {
		List<byte[]> messages = new ArrayList<byte[]>();

		/**
		 * Extremes
		 */
		messages.add(new byte[0]);
		repeats.add(1);
		messages.add("a".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("ab".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("abc".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("The quick brown fox jumps over the lazy dog.".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("message digest".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("abcdefghijklmnopqrstuvwxyz".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1);
		messages.add("1234567890".getBytes(StandardCharsets.US_ASCII));
		repeats.add(8);
		messages.add("a".getBytes(StandardCharsets.US_ASCII));
		repeats.add(1000000);
		//messages.add("0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII));
		//repeats.add(0x2000000);

		/**
		 * Purely random vectors
		 */
		for (int i = 0; i < 500; i++) {
			int mask = (1 << (r.nextInt(10))) - 1;
			byte[] message = new byte[r.nextInt() & mask];
			r.nextBytes(message);
			messages.add(message);
			int rep;
			if (r.nextInt(5) == 0) {
				rep = r.nextInt(50);
			} else {
				rep = 1;
			}
			repeats.add(rep);
		}

		return messages;
	}

	public static List<String> generateSHA256Vectors(List<byte[]> messages, List<Integer> repeats) {
		List<String> lines = new ArrayList<String>();

		List<byte[]> SHA256Hashes = generateHashes(messages, repeats, SHA256.getSHA256MessageDigest());
		List<byte[]> SHA512Hashes = generateHashes(messages, repeats, SHA512.getSHA512MessageDigest());
		List<byte[]> RIPEMD160Hashes = generateHashes(messages, repeats, RIPEMD160.getRIPEMD160MessageDigest());
		List<byte[]> DSHA256Hashes = generateHashes(messages, repeats, SHA256.getDSHA256MessageDigest());
		List<byte[]> DSHA512Hashes = generateHashes(messages, repeats, SHA512.getDSHA512MessageDigest());
		List<byte[]> DRIPEMD160Hashes = generateHashes(messages, repeats, RIPEMD160.getDRIPEMD160MessageDigest());

		lines.add("tw_u8* tw_hash_test_vector_messages[] = {");

		for (byte[] message : messages) {
			lines.add("    " + Convert.bytesToU8(false, message) + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("int tw_hash_test_vector_message_lengths[] = {");

		for (byte[] message : messages) {
			lines.add("    " + message.length + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("int tw_hash_test_vector_message_repeats[] = {");

		for (Integer r : repeats) {
			lines.add("    " + r + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("tw_u512 tw_sha256_test_vector_hashes[] = {");

		for (byte[] hash : SHA256Hashes) {
			lines.add("    " + Convert.LEBytesToU512(hash) + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("tw_u512 tw_sha512_test_vector_hashes[] = {");

		for (byte[] hash : SHA512Hashes) {
			lines.add("    " + Convert.LEBytesToU512(hash) + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("tw_u512 tw_ripemd160_test_vector_hashes[] = {");

		for (byte[] hash : RIPEMD160Hashes) {
			lines.add("    " + Convert.LEBytesToU512(hash) + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("tw_u512 tw_dsha256_test_vector_hashes[] = {");

		for (byte[] hash : DSHA256Hashes) {
			lines.add("    " + Convert.LEBytesToU512(hash) + ",");
		}

		lines.add("  };");
		lines.add("");

		lines.add("tw_u512 tw_dsha512_test_vector_hashes[] = {");

		for (byte[] hash : DSHA512Hashes) {
			lines.add("    " + Convert.LEBytesToU512(hash) + ",");
		}

		lines.add("  };");
		lines.add("");
		lines.add("tw_u512 tw_dripemd160_test_vector_hashes[] = {");

		for (byte[] hash : DRIPEMD160Hashes) {
			lines.add("    " + Convert.LEBytesToU512(hash) + ",");
		}

		lines.add("  };");
		lines.add("");
		lines.add("#define HASH_TEST_VECTORS_LENGTH " + messages.size());

		return lines;
	}

	private static List<byte[]> generateHashes(List<byte[]> messages, List<Integer> repeats, MessageDigest md) {
		List<byte[]> hashes = new ArrayList<byte[]>(messages.size());
		for (int i = 0; i < messages.size(); i++) {
			md.reset();
			byte[] message = messages.get(i);
			int repeat = repeats.get(i);
			for (int j = 0; j < repeat; j++) {
				md.update(message);
			}
			byte[] hash = md.digest();
			hashes.add(hash);
		}
		return hashes;
	}
}

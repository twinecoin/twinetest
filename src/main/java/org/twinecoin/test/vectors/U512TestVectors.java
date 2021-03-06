package org.twinecoin.test.vectors;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Class to generate test vectors for the tw_u512 class.<br>
 * <br>
 * This ensures that the test vectors are generated by a separate
 * implementation.
 */
public class U512TestVectors {

	public final static BigInteger U512_ZERO = BigInteger.ZERO;
	public final static BigInteger U512_HALF_MAX = BigInteger.ONE.shiftLeft(511);
	public final static BigInteger U512_MAX = BigInteger.ONE.shiftLeft(512).subtract(BigInteger.ONE);
	public final static BigInteger U384_MAX = BigInteger.ONE.shiftLeft(384).subtract(BigInteger.ONE);
	public final static BigInteger U256_MAX = BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE);
	public final static BigInteger U128_MAX = BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE);
	public final static BigInteger U64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE);

	private final static long[] edgeValues;

	static {
		/**
		 * The u512 class uses 64-bit unsigned words internally.
		 *
		 * Each word is initialised to one of the following.  Words near the extremes
		 * are assumed to give errors.
		 * 
		 *   0x00000000
		 *   0x00000001
		 *   0xFFFFFFFE
		 *   0xFFFFFFFF
		 *   Random value
		 */
		long[] longEdgeValues = new long[] {
				0x00000000_00000000L, 
				0x00000000_00000001L,
				0x00000000_0000FFFEL,
				0x00000000_0000FFFFL,
				0x00000000_00010000L,
				0x00000000_00010001L,
				0x00000000_FFFFFFFEL, 
				0x00000000_FFFFFFFFL,
				0x0000FFFF_FFFFFFFEL,
				0x0000FFFF_FFFFFFFFL,
				0x00010000_00000000L,
				0x00010000_00000001L,
				0x00000001_00000000L,
				0x00000001_00000001L,
				0x00000002_00000002L,
				0xFFFFFFFE_FFFFFFFEL,
				0xFFFFFFFE_FFFFFFFFL,
				0xFFFFFFFF_FFFFFFFEL,
				0xFFFFFFFF_FFFFFFFFL};

		int[] intEdgeValues = new int[] {
				0x00000000, 
				0x00000001, 
				0x00000002,
				0x7FFFFFFE,
				0x7FFFFFFF,
				0x80000000,
				0x80000001,
				0x80000002,
				0xFFFFFFFE, 
				0xFFFFFFFF};

		edgeValues = new long[intEdgeValues.length * intEdgeValues.length + longEdgeValues.length];

		System.arraycopy(longEdgeValues, 0, edgeValues, 0, longEdgeValues.length);

		for (int i = 0; i < intEdgeValues.length; i++) {
			int k = longEdgeValues.length + i * intEdgeValues.length;
			for (int j = 0; j < intEdgeValues.length; j++) {
				edgeValues[k + j] = Convert.twoIntsToLong(intEdgeValues[i], intEdgeValues[j]);
			}
		}
	}

	public static List<String> generateVectors() {
		Random r = getRandom();

		List<List<BigInteger>> quad = generateBigIntegerList(r);

		List<String> lines = new ArrayList<String>();

		lines.addAll(generateU512BinaryOperatorVectors(quad.get(0), quad.get(1), quad.get(2), quad.get(3)));
		lines.add("");
		lines.addAll(generateU512xU64BinaryOperatorVectors(r, quad.get(0), quad.get(3)));

		return lines;
	}

	public static Random getRandom() {
		Random r = new Random();

		// Seed random so that results are consistent
		r.setSeed(0x280e788cff6ec2bbL);
		return r;
	}

	public static List<List<BigInteger>> generateBigIntegerList(Random r) {
		List<BigInteger> integerList = new ArrayList<BigInteger>();

		long[] value = new long[8];
		for (int i = 0; i < 500000; i++) {
			for (int j = 0; j < value.length; j++) {
				int option = r.nextInt(edgeValues.length);
				if (r.nextInt(4) == 0) {
					value[j] = r.nextLong();
				} else {
					value[j] = edgeValues[option];
				}
			}
			integerList.add(Convert.longToBigInteger(value));
		}

		List<BigInteger> aList = new ArrayList<BigInteger>();
		List<BigInteger> bList = new ArrayList<BigInteger>();
		List<BigInteger> sectionList = new ArrayList<BigInteger>();

		BigInteger sectionNumber = BigInteger.ONE;

		/**
		 * Extremes
		 */
		BigInteger[] extremes = new BigInteger[] {
			BigInteger.ZERO,                      // 0
			BigInteger.ONE,                       // 1
			U128_MAX.subtract(BigInteger.ONE),    // 2^128 - 2
			U128_MAX,                             // 2^128 - 1
			U128_MAX.add(BigInteger.ONE),         // 2^128
			U128_MAX.add(BigInteger.valueOf(2)),  // 2^128 + 1
			U256_MAX.subtract(BigInteger.ONE),    // 2^256 - 2
			U256_MAX,                             // 2^256 - 1
			U256_MAX.add(BigInteger.ONE),         // 2^256
			U256_MAX.add(BigInteger.valueOf(2)),  // 2^256 + 1
			U384_MAX.subtract(BigInteger.ONE),    // 2^384 - 2
			U384_MAX,                             // 2^384 - 1
			U384_MAX.add(BigInteger.ONE),         // 2^384
			U384_MAX.add(BigInteger.valueOf(2)),  // 2^384 + 1
			U512_MAX.subtract(BigInteger.ONE),    // 2^512 - 2
			U512_MAX                              // 2^512 - 1
		};

		for (int i = 0; i < extremes.length; i++) {
			for (int j = 0; j < extremes.length; j++) {
				aList.add(extremes[i]);
				bList.add(extremes[j]);
				sectionList.add(sectionNumber);
			}
		}

		/**
		 * Divide by zero
		 */
		sectionNumber = BigInteger.valueOf(2);

		for (int i = 0; i < 10; i++) {
			aList.add(integerList.get(r.nextInt(integerList.size())));
			bList.add(U512_ZERO);
			sectionList.add(sectionNumber);
		}

		aList.add(U512_MAX);
		bList.add(U512_ZERO);
		sectionList.add(sectionNumber);

		/**
		 * Single bits set
		 */
		sectionNumber = BigInteger.valueOf(3);

		for (int i = 0; i < 8; i++) {
			for (int j = 0; j < 8; j++) {
				aList.add(BigInteger.ONE.shiftLeft(i * 64 + r.nextInt(64)));
				bList.add(BigInteger.ONE.shiftLeft(j * 64 + r.nextInt(64)));
				sectionList.add(sectionNumber);
			}
		}

		for (int i = 0; i < 12; i++) {
			for (int j = 0; j < 12; j++) {
				for (int k = 0; k < (i == 0 ? 1 : 2); k++) {
					for (int m = 0; m < (j == 0 ? 1 : 2); m++) {
						aList.add(BigInteger.ONE.shiftLeft(i * 16 - k));
						bList.add(BigInteger.ONE.shiftLeft(j * 16 - m));
						sectionList.add(sectionNumber);
					}
				}
			}
		}

		aList.add(U512_HALF_MAX);
		bList.add(U512_HALF_MAX);
		sectionList.add(sectionNumber);

		/**
		 * Almost equal
		 */
		sectionNumber = BigInteger.valueOf(4);
		for (int i = 0; i < 10; i++) {
			BigInteger v = integerList.get(r.nextInt(integerList.size()));
			aList.add(v);
			bList.add(v.add(BigInteger.valueOf(i - 5)));
			sectionList.add(sectionNumber);
		}

		/**
		 * Single bit different
		 */
		sectionNumber = BigInteger.valueOf(5);
		for (int i = 0; i < 16; i++) {
			BigInteger ref = new BigInteger(512, r);
			aList.add(ref);
			BigInteger bit = BigInteger.ONE.shiftLeft(r.nextInt(32) + (32 * i));
			bList.add(ref.xor(bit));
			sectionList.add(sectionNumber);
		}

		/**
		 * Directed vectors
		 */
		sectionNumber = BigInteger.valueOf(6);
		for (int i = 0; i < 500; i++) {
			aList.add(integerList.get(r.nextInt(integerList.size())));
			bList.add(integerList.get(r.nextInt(integerList.size())));
			sectionList.add(sectionNumber);
		}

		/**
		 * Purely random vectors
		 */
		sectionNumber = BigInteger.valueOf(7);
		for (int i = 0; i < 500; i++) {
			aList.add(new BigInteger(512, r));
			bList.add(new BigInteger(512, r));
			sectionList.add(sectionNumber);
		}

		/**
		 * Random vectors where a is a multiple of b
		 */
		sectionNumber = BigInteger.valueOf(8);
		for (int i = 0; i < 500; i++) {
			BigInteger a = new BigInteger(512, r);
			BigInteger b = new BigInteger(512, r);

			int aSize = r.nextInt(512);
			int bSize = r.nextInt(512 - aSize);

			a = a.and(BigInteger.ONE.shiftLeft(aSize - 1).subtract(BigInteger.ONE));
			b = b.and(BigInteger.ONE.shiftLeft(bSize - 1).subtract(BigInteger.ONE));

			if (aSize == 0) {
				a = BigInteger.ZERO;
			}

			if (bSize == 0) {
				b = BigInteger.ZERO;
			}

			a = a.multiply(b);

			aList.add(a);
			bList.add(b);
			sectionList.add(sectionNumber);
		}

		/**
		 * Purely random vectors, with some half width
		 */
		sectionNumber = BigInteger.valueOf(9);
		for (int i = 0; i < 500; i++) {
			aList.add(new BigInteger(r.nextBoolean() ? 512 : 256, r));
			bList.add(new BigInteger(r.nextBoolean() ? 512 : 256, r));
			sectionList.add(sectionNumber);
		}


		/**
		 * Purely random vectors of various lengths
		 */
		sectionNumber = BigInteger.valueOf(10);
		for (int i = 1; i <= 32; i++) {
			for (int j = 0; j < 20; j++) {
				aList.add(new BigInteger(16 * i, r));
				bList.add(new BigInteger(16 * i, r));
				sectionList.add(sectionNumber);
			}
		}

		/**
		 * Directed vectors of various lengths
		 */
		sectionNumber = BigInteger.valueOf(11);
		for (int i = 1; i <= 32; i++) {
			for (int j = 0; j < 20; j++) {
				BigInteger a = integerList.get(r.nextInt(integerList.size()));
				a = a.and(BigInteger.ONE.shiftLeft(16 * i).subtract(BigInteger.ONE));
				BigInteger b = integerList.get(r.nextInt(integerList.size()));
				b = b.and(BigInteger.ONE.shiftLeft(16 * (1 + r.nextInt(32))).subtract(BigInteger.ONE));
				aList.add(a);
				bList.add(b);
				sectionList.add(sectionNumber);
			}
		}

		List<BigInteger> cList = new ArrayList<BigInteger>();

		int size = aList.size();
		for (int i = 0; i < size; i++) {
			if (r.nextBoolean()) {
				cList.add(aList.get(r.nextInt(size)));
			} else {
				cList.add(bList.get(r.nextInt(size)));
			}
		}

		sectionNumber = BigInteger.valueOf(12);

		for (int i = 0; i < 50; i++) {
			BigInteger a = new BigInteger(r.nextBoolean()? 128 : 512, r);
			aList.add(a);
			bList.add(a);
			cList.add(a);
			sectionList.add(sectionNumber);
		}

		List<List<BigInteger>> quad = new ArrayList<List<BigInteger>>(3);
		quad.add(aList);
		quad.add(bList);
		quad.add(cList);
		quad.add(sectionList);
		return quad;
	}

	public static List<String> generateU512BinaryOperatorVectors(List<BigInteger> aList, List<BigInteger> bList, 
			                                                     List<BigInteger> cList, List<BigInteger> sectionList) {
		List<String> lines = new ArrayList<String>();

		lines.add("#include \"../../src/math/src/tw_uint.h\"");

		lines.add("typedef struct _tw_u512_test_vector_512x512 {");
		lines.add("  tw_u512 a;             // a");
		lines.add("  tw_u512 b;             // b");
		lines.add("  tw_u512 c;             // c");
		lines.add("  int a_equal_b;         // a == b");
		lines.add("  int a_comp_b;          // (a < b) ? -1 : (a == b) ? 0 : 1");
		lines.add("  tw_u512 a_add_b;       // a + b");
		lines.add("  int a_add_b_carry;     // Carry");
		lines.add("  tw_u512 a_sub_b;       // a - b");
		lines.add("  int a_sub_b_borrow;    // Borrow");
		lines.add("  tw_u512 a_mul_b;       // a * b");
		lines.add("  int a_mul_b_overflow;  // Overflow");
		lines.add("  tw_u512 a_div_b;       // a / b");
		lines.add("  tw_u512 a_rem_b;       // a / b");
		lines.add("  int div_by_0;          // divide by 0");
		lines.add("  tw_u512 a_add_c_mod_b; // (a + c) % b");
		lines.add("  tw_u512 a_pow_c_mod_b; // pow(a, c) % b");
		lines.add("} tw_u512_test_vector_512x512;");
		lines.add("");

		lines.add("tw_u512_test_vector_512x512 u512_test_vectors_512x512[] =");
		lines.add("  {");

		String align = 
				"                                                                                               " +
				"                                                                                               ";

		BigInteger lastSection = BigInteger.valueOf(-1);

		for (int i = 0; i < aList.size(); i++) {
			BigInteger a = aList.get(i);
			BigInteger b = bList.get(i);
			BigInteger c = cList.get(i);

			BigInteger section = sectionList.get(i);

			BigInteger add = a.add(b);
			BigInteger sub = a.subtract(b);
			BigInteger mul = a.multiply(b);
			BigInteger div = BigInteger.ZERO.equals(b) ? BigInteger.ZERO : a.divide(b);
			BigInteger rem = BigInteger.ZERO.equals(b) ? BigInteger.ZERO : a.remainder(b);
			BigInteger modAdd = BigInteger.ZERO.equals(b) ? BigInteger.ZERO : a.add(c).remainder(b);
			BigInteger pow = BigInteger.ZERO.equals(b) ? BigInteger.ZERO : a.modPow(c, b);

			if (!lastSection.equals(section)) {
				lastSection = section;
				lines.add("    // <<<<<<<<<<<<<<<<< Section " + section + " >>>>>>>>>>>>>>>>>");
			}
			lines.add("    // Vector " + i);
			lines.add("    // a = " + String.format("0x%0128x", a));
			lines.add("    // b = " + String.format("0x%0128x", b));
			lines.add("    // c = " + String.format("0x%0128x", c));
			lines.add("    {");
			lines.add("      " + Convert.bigIntegerToU512(a) + ",            // a");
			lines.add("      " + Convert.bigIntegerToU512(b) + ",            // b");
			lines.add("      " + Convert.bigIntegerToU512(c) + ",            // c");
			lines.add("      " + (a.equals(b) ? "1," : "0,") + align + "     // equals");
			lines.add("      " + a.compareTo(b) + "," + align + (a.compareTo(b) >= 0 ? " " : "") + "    // compare");
			lines.add("      " + Convert.bigIntegerToU512(add) + ",            // a + b");
			lines.add("      " + (add.compareTo(U512_MAX) > 0 ? 1 : 0) + "," + align + "     // carry");
			lines.add("      " + Convert.bigIntegerToU512(sub) + ",            // a - b");
			lines.add("      " + (sub.compareTo(BigInteger.ZERO) < 0 ? 1 : 0) + "," + align + "     // borrow");
			lines.add("      " + Convert.bigIntegerToU512(mul) + ",            // a * b");
			lines.add("      " + (mul.compareTo(U512_MAX) > 0 ? 1 : 0) + "," + align + "     // overflow");
			lines.add("      " + Convert.bigIntegerToU512(div) + ",            // a / b");
			lines.add("      " + Convert.bigIntegerToU512(rem) + ",            // a % b");
			lines.add("      " + (b.compareTo(BigInteger.ZERO) == 0 ? 1 : 0) + "," + align + "     // div_by_zero");
			lines.add("      " + Convert.bigIntegerToU512(modAdd) + ",            // (a + c) mod b");
			lines.add("      " + Convert.bigIntegerToU512(pow) + ",            // pow(a,  c) mod b");
			lines.add("    " + ((i == aList.size() - 1) ? "}" : "},"));
		}
		lines.add("  };");
		lines.add("");
		lines.add("#define U512_TEST_VECTORS_512X512_LENGTH " + aList.size());

		return lines;
	}

	public static List<String> generateU512xU64BinaryOperatorVectors(Random r, List<BigInteger> aList, List<BigInteger> sectionList) {
		List<String> lines = new ArrayList<String>();

		lines.add("typedef struct _tw_u512_test_vector_512x64 {");
		lines.add("  tw_u512 a;                // a");
		lines.add("  tw_u64 b;                 // b");
		lines.add("  tw_u32 s;                 // shift (32-bit words)");
		lines.add("  tw_u512 a_lshift;         // a << (s & 511)");
		lines.add("  tw_u32 a_lshift_overflow; // left shift overflow");
		lines.add("  tw_u512 a_rshift;         // a >> (s & 511)");
		lines.add("  tw_u32 a_rshift_underflow;// right shift underflow");
		lines.add("} tw_u512_test_vector_512x64;");
		lines.add("");

		lines.add("tw_u512_test_vector_512x64 u512_test_vectors_512x64[] =");
		lines.add("  {");

		String align = 
				"                                                                                " +
				"                                                                                ";

		BigInteger lastSection = BigInteger.valueOf(-1);

		for (int i = 0; i < aList.size(); i++) {
			BigInteger a = aList.get(i);
			BigInteger section = sectionList.get(i);
			long bLong;

			if (r.nextBoolean()) {
				bLong = r.nextLong();
			} else {
				bLong = edgeValues[r.nextInt(edgeValues.length)];
			}

			BigInteger b = BigInteger.valueOf(bLong).and(U64_MAX);

			int s = r.nextInt();

			int bitShift = s & 511;

			BigInteger aLeftShift = a.shiftLeft(bitShift);

			int leftShiftOverflow = aLeftShift.compareTo(U512_MAX) > 0 ? 1 : 0;

			BigInteger aRightShift = a.shiftRight(bitShift);

			int rightShiftUnderflow = a.and(BigInteger.ONE.shiftLeft(bitShift).subtract(BigInteger.ONE)).equals(BigInteger.ZERO) ?
					                  0 : 1;

			if (!lastSection.equals(section)) {
				lastSection = section;
				lines.add("    // <<<<<<<<<<<<<<<<< Section " + section + " >>>>>>>>>>>>>>>>>");
			}
			lines.add("    // Vector " + i);
			lines.add("    // a = " + String.format("0x%0128x", a));
			lines.add("    // b = " + String.format("0x%016x", b));
			lines.add("    {");
			lines.add("      " + Convert.bigIntegerToU512(a) + ",            // a");
			lines.add("      " + String.format("0x%016xULL", b) + "," + align + "               // b");
			lines.add("      " + String.format("0x%08xU", s) + "," + align + "                         // s");
			lines.add("      " + Convert.bigIntegerToU512(aLeftShift) + ",            // a_lshift");
			lines.add("      " + String.format("0x%08xU", leftShiftOverflow) + "," + align + "                         // a_lshift_overflow");
			lines.add("      " + Convert.bigIntegerToU512(aRightShift) + ",            // a_rshift");
			lines.add("      " + String.format("0x%08xU", rightShiftUnderflow) + "," + align + "                         // a_rshift_underflow");
			lines.add("    " + ((i == aList.size() - 1) ? "}" : "},"));
		}
		lines.add("  };");
		lines.add("");
		lines.add("#define U512_TEST_VECTORS_512X64_LENGTH " + aList.size());

		return lines;
	}
}

package org.twinecoin.test.crypt;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

public class BouncyCastleLoader {
	private final static Provider bouncyCastleProvider;

	private final static String SHA256Expected = "4c7fb5f7fb043fedc4b7e7af88871050f61af8dea7aaade87f8ebd60e509cd89";

	private final static String jarFilename = "bcprov-jdk15on-1.57.jar";

	static {
		File dir = new File("jars");
		dir.mkdirs();

		boolean jarPresent = false;

		File f = new File(dir, jarFilename);

		if (f.exists()) {
			jarPresent = checkSHA256(f, SHA256Expected);
		}

		Class<? extends Thread> currentThreadClass = Thread.currentThread().getClass();

		if (!jarPresent) {
			InputStream in = currentThreadClass.getResourceAsStream("/" + jarFilename);
			OutputStream out = null;
			if (in != null) {
				try {
					out = new FileOutputStream(f);
					byte[] buf = new byte[16384];
					int read = 1;
					while (read > 0) {
						read = in.read(buf);
						if (read > 0) {
							out.write(buf, 0, read);
						}
					}
				} catch (IOException e) {
				} finally {
					try {
						if (out != null) {
							out.close();
						}
					} catch (IOException e) {
					} finally {
						try {
							in.close();
						} catch (IOException e) {}
					}
				}
			}
			jarPresent = checkSHA256(f, SHA256Expected);
		}

		URL url  = null;

		if (jarPresent) {
			try {
				url = f.toURI().toURL();
			} catch (MalformedURLException e1) {
			}
		}

		URLClassLoader urlClassLoader = null;

		if (url != null) {
			URL[] childURLs = new URL[] {url};
			ClassLoader parentClassLoader = currentThreadClass.getClassLoader();
			urlClassLoader = URLClassLoader.newInstance(childURLs, parentClassLoader);
		}

		Class<?> bouncyCastleProviderClass = null;

		if (urlClassLoader != null) {
			try {
				bouncyCastleProviderClass = urlClassLoader.loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider");
			} catch (ClassNotFoundException e) {
			}
		}

		Provider provider = null;

		if (bouncyCastleProviderClass != null) {
			try {
				provider = (Provider) bouncyCastleProviderClass.newInstance();
			} catch (InstantiationException e) {
			} catch (IllegalAccessException e) {
			} catch (ClassCastException e) {
			}
		}

		if (provider != null) {
			Security.addProvider(provider);
		}

		bouncyCastleProvider = provider;
	}

	/**
	 * Loads the Bouncy Castle Provider if not already loaded.<br>
	 *
	 * @return true if the provider has been loaded
	 */
	public static boolean init() {
		return bouncyCastleProvider != null;
	}

	private static boolean checkSHA256(File f, String expected) {
		byte[] decoded = decodeHex(expected);
		if (decoded == null) {
			return false;
		}
		byte[] digest = null;
		MessageDigest md;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e1) {
			// This should not be possible
			return false;
		}
		FileInputStream in = null;
		try {
			in = new FileInputStream(f);

			byte[] buf = new byte[16384];

			int read = 1;
			while (read > 0) {
				read = in.read(buf);
				if (read > 0) {
					md.update(buf, 0, read);
				}
			}
			digest = md.digest();
		} catch (IOException e) {
			return false;
		} finally {
			if (in != null) {
				try {
					in.close();
				} catch (IOException e) {}
			}
		}

		return Arrays.equals(digest, decoded);
	}

	private static byte[] decodeHex(String hex) {
		if ((hex.length() & 1) != 0) {
			return null;
		}

		byte[] decoded = new byte[hex.length() >> 1];

		int j = 0;
		for (int i = 0; i < decoded.length; i++) {
			int v = (hexCharToInt(hex.charAt(j)) << 4) + hexCharToInt(hex.charAt(j + 1));
			if (v < 0) {
				return null;
			}
			decoded[i] = (byte) v;
			j += 2;
		}

		return decoded;
	}

	private static int hexCharToInt(char c) {
		if (c >= '0' && c <= '9') {
			return c - '0';
		} else if (c >= 'A' && c <= 'F') {
			return 10 + c - 'A';
		} else if (c >= 'a' && c <= 'f') {
			return 10 + c - 'a';
		} else {
			return -256;
		}
	}

}

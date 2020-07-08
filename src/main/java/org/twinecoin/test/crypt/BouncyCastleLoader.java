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
	private final static String SHA256Expected = "e78f96eb59066c94c94fb2d6b5eb80f52feac6f5f9776898634f8addec6e2137";

	private final static String jarFilename = "bcprov-jdk15on-1.65.jar";

	private final static String bouncyCastleProviderName = "org.bouncycastle.jce.provider.BouncyCastleProvider";

	private final static Provider bouncyCastleProvider;

	private final static URLClassLoader urlClassLoader;

	static {
		File dir = new File("jars");
		dir.mkdirs();

		boolean jarPresent = false;

		File f = new File(dir, jarFilename);

		if (f.exists()) {
			jarPresent = checkSHA256(f, SHA256Expected);
		}

		if (!jarPresent) {
			InputStream in = BouncyCastleLoader.class.getResourceAsStream("/" + jarFilename);
			try {
				if (in != null) {
					OutputStream out = null;
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
						if (out != null) {
							try {
								out.close();
							} catch (IOException e) {}
						}

					}
				}
			} finally {
				if (in != null) {
					try {
						in.close();
					} catch (IOException e) {}
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

		Provider prov = null;
		URLClassLoader urlCL = null;

		if (url != null) {
			ClassLoader systemClassLoader = ClassLoader.getSystemClassLoader();

			if (systemClassLoader instanceof URLClassLoader) {
				URL[] systemURLs = ((URLClassLoader) systemClassLoader).getURLs();
				if (systemURLs != null) {
					URL[] newURLs = new URL[systemURLs.length + 1];
					System.arraycopy(systemURLs, 0, newURLs, 0, systemURLs.length);
					newURLs[newURLs.length - 1] = url;
					urlCL = new URLClassLoader(newURLs, systemClassLoader);
					Class<?> clazz = null;
					try {
						clazz = urlCL.loadClass(bouncyCastleProviderName);
					} catch (ClassNotFoundException e) {
					}
					if (clazz != null) {
						try {
							Object p = clazz.newInstance();
							if (p instanceof Provider) {
								prov = (Provider) p;
							}
						} catch (InstantiationException e) {
						} catch (IllegalAccessException e) {
						}
					}
				}
			}
		}

		urlClassLoader = urlCL;

		if (prov != null) {
			Security.addProvider(prov);
		}

		bouncyCastleProvider = prov;
	}

	/**
	 * Initializes the Bouncy Castle Provider<br>
	 * <br>
	 * The Bouncy Castle Provider is loaded with a new ClassLoader and
	 * a runnable of the named class is instantiated with the ClassLoader and 
	 * the .run() method is called.<br>
	 * <br>
	 *
	 * @return true if the provider has been loaded
	 */
	public static boolean init(String runnableName) {
		if (bouncyCastleProvider == null || urlClassLoader == null) {
			return false;
		}
		Class<?> clazz = null;
		try {
			clazz	= urlClassLoader.loadClass(runnableName);
		} catch (ClassNotFoundException e) {
			return false;
		}
		if (clazz == null) {
			return false;
		}
		Runnable r = null;
		try {
			r = (Runnable) clazz.newInstance();
		} catch (InstantiationException e) {
		} catch (IllegalAccessException e) {
		}
		if (r == null) {
			return false;
		}
		r.run();
		return true;
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

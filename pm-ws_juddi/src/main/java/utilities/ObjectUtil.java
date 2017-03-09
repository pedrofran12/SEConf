package utilities;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

public abstract class ObjectUtil {

	// GENERAL READ
	public static <T> T readObject(InputStream is, Class<T> c) {
		ObjectInput oi = null;
		T obj = null;
		try {
			oi = new ObjectInputStream(is);
			obj = c.cast(oi.readObject());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				oi.close();
			} catch (Exception e) {
			}
		}
		return obj;
	}

	// GENERAL WRITE
	public static <T> boolean writeObject(T obj, OutputStream out) {
		boolean success = false;
		ObjectOutput oo = null;
		try {
			oo = new ObjectOutputStream(out);
			oo.writeObject(obj);
			oo.flush();
			success = true;
		} catch (Exception e) {
			//e.printStackTrace();
		} finally {
			try {
				oo.close();
			} catch (Exception e) {
			}
		}
		return success;
	}

	// BYTE READ
	public static <T> T readObjectBytes(byte[] array, Class<T> c) {
		ByteArrayInputStream bais = new ByteArrayInputStream(array);
		T obj = null;
		try {
			obj = readObject(bais, c);
		} catch (Exception e) {
			//e.printStackTrace();
		} finally {
			try {
				bais.close();
			} catch (Exception e) {
			}
		}
		return obj;
	}

	// BYTE WRITE
	public static <T> byte[] writeObjectBytes(T obj) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] array = null;
		try {
			boolean success = writeObject(obj, baos);
			if (success) {
				array = baos.toByteArray();
			}
		} catch (Exception e) {
			//e.printStackTrace();
		} finally {
			try {
				baos.close();
			} catch (Exception e) {
			}
		}
		return array;
	}

	// FILE READ
	public static <T> T readObjectFile(File file, Class<T> c) {
		FileInputStream fis = null;
		T obj = null;
		try {
			fis = new FileInputStream(file);
			obj = readObject(fis, c);
		} catch (Exception e) {
			//e.printStackTrace();
		} finally {
			try {
				fis.close();
			} catch (Exception e) {
			}
		}
		return obj;
	}

	// FILE WRITE
	public static <T> boolean writeObjectFile(File file, T obj) {
		boolean success = false;
		FileOutputStream fos = null;
		try {
			fos = new FileOutputStream(file);
			success = writeObject(obj, fos);
		} catch (Exception e) {
			//e.printStackTrace();
		} finally {
			try {
				fos.close();
			} catch (Exception e) {
			}
		}
		return success;
	}

	// FILENAME READ
	public static <T> T readObjectFile(String fileName, Class<T> c) {
		return readObjectFile(new File(fileName), c);
	}

	// FILENAME WRITE
	public static <T> boolean writeObjectFile(String fileName, T obj) {
		return writeObjectFile(new File(fileName), obj);
	}
}

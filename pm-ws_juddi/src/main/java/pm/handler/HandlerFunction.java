package pm.handler;

import javax.xml.soap.SOAPBody;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;

public class HandlerFunction {

    public static MessageDigest Object2Hash(MessageDigest md, Object obj) throws Exception {// needs
                                                                                            // revision

        if (md == null) {
            md = MessageDigest.getInstance("SHA-256");
        }

        md.update(Object2Bytes(obj));

        return md;
    }

    public static byte[] digestMessage(MessageDigest md) throws Exception {

        if (md == null) {
            throw new Exception(); // needs to be corrected
        }

        return md.digest();
    }

    private static byte[] Object2Bytes(Object obj) throws Exception {

        // Convert Object To bytes!
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(obj);
        out.flush();

        return bos.toByteArray();
    }

    private static Object byte2Object(byte[] byt) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(byt);
        ObjectInput in = new ObjectInputStream(bis);

        return in.readObject();
    }
}

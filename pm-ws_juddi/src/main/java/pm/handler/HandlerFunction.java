package pm.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import pm.exception.InvalidMessageDigestException;

public class HandlerFunction {

    // - DIGEST - //
    public static MessageDigest object2Hash(MessageDigest md, Object obj) throws NoSuchAlgorithmException, IOException {
        
        if (md == null) {
            md = MessageDigest.getInstance("SHA-256");
        }
        md.update(object2Bytes(obj));
        return md;
    }

    public static byte[] digestMessage(MessageDigest md) throws InvalidMessageDigestException {

        if (md == null) {
            throw new InvalidMessageDigestException(); // needs to be corrected
        }
        return md.digest();
    }

    private static byte[] object2Bytes(Object obj) throws IOException{

        // Convert Object To bytes!
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(obj);
        out.flush();

        return bos.toByteArray();
    }

    //useless but if needed is created!
    private static Object byte2Object(byte[] byt) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(byt);
        ObjectInput in = new ObjectInputStream(bis);

        return in.readObject();
    }
    
    // - KEY PART - 
}

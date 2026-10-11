// tp-deser-java.java: Unsafe deserialization with ObjectInputStream
import java.io.*;

public class InsecureDeserializer {
    public static Object deserialize(byte[] data) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        // VULNERABLE: deserializing untrusted data
        return ois.readObject();
    }
}

package pm.exception;

public class KeyAlreadyExistsException extends Exception {

    private static String message = "Key already Exists";
    
    public KeyAlreadyExistsException(String mess){
        super(mess);
    }
    public KeyAlreadyExistsException(){
        super(message);
    }
}

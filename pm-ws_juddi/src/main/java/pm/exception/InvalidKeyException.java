package pm.exception;

public class InvalidKeyException extends Exception {
    
    private static String message = "Invalid Key used";
    
    public InvalidKeyException(String mess){
        super(mess);
    }
    public InvalidKeyException(){
        super(message);
}

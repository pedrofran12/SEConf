package pm.exception;

public class InvalidKeyException extends Exception {
    

    private static final long serialVersionUID = 1L;

    private static String message = "Invalid Key used";
    
    public InvalidKeyException(String mess){
        super(mess);
    }
    public InvalidKeyException(){
        super(message);
    }
}


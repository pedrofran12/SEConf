package pm.exception.cli;

public class NoSessionException extends Exception {
    private static final long serialVersionUID = 1L;

    protected static final String message = "Session currently being used";
    
    public NoSessionException(String mess) {
        super(mess);
    }
    
    public NoSessionException() {
        super(message);
    }
}

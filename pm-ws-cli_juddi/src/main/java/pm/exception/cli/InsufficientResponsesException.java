package pm.exception.cli;

public class InsufficientResponsesException extends ClientException {
    private static final long serialVersionUID = 1L;

    protected static final String message = "Could not get sufficient responses";
    
    public InsufficientResponsesException(String mess) {
        super(mess);
    }
    
    public InsufficientResponsesException() {
        super(message);
    }
}
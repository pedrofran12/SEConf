package pm.exception.cli;

public class NoSessionException extends ClientException {
    private static final long serialVersionUID = 1L;

    protected static final String message = "No opened session";
    
    public NoSessionException(String mess) {
        super(mess);
    }
    
    public NoSessionException() {
        super(message);
    }
}

package pm.exception.cli;


public class AlreadyExistsLoggedUserException extends ClientException {

    private static final long serialVersionUID = 1L;

    protected static final String message = "Session currently being used";
    
    public AlreadyExistsLoggedUserException(String mess){
        super(mess);
    }
    public AlreadyExistsLoggedUserException(){
        super(message);
    }
}

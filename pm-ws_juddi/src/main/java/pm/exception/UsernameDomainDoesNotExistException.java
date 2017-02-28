package pm.exception;

public class UsernameDomainDoesNotExistException extends PasswordManagerException {

    private static final long serialVersionUID = 1L;

    private static final String message = "Username/Domain does not exists";
    
	public UsernameDomainDoesNotExistException() {
		super(message);
	}
	
	public UsernameDomainDoesNotExistException(String msg) {
		super(msg);
	}
}
package pm.exception;

public abstract class PasswordManagerException extends Exception {
	private static final String message = "PasswordMAnager exception";
	
	public PasswordManagerException() {
		super(message);
	}
	
	public PasswordManagerException(String msg) {
		super(msg);
	}
}

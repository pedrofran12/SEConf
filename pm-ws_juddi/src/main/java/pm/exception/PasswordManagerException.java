package pm.exception;

public abstract class PasswordManagerException extends Exception{

	private static final long serialVersionUID = 1L;

	public PasswordManagerException(String msg) {
		super(msg);
	}
}

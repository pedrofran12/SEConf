package pm.exception.cli;

public class InvalidKeyStoreException extends ClientException {

	private static final long serialVersionUID = 1L;
	
	protected static final String message = "Invalid KeyStore";
	
	public InvalidKeyStoreException(String mess) {
		super(mess);
	}
	
	public InvalidKeyStoreException(){
        super(message);
    }

}

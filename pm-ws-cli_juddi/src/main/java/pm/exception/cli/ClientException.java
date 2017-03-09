package pm.exception.cli;


public abstract class ClientException extends Exception {

    private static final long serialVersionUID = 1L;
    
    public ClientException(String mess){
        super(mess);
    }
}

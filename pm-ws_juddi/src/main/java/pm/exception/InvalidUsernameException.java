package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InvalidUsernameException", propOrder = {
    "message"
})
public class InvalidUsernameException extends Exception {

    private static final long serialVersionUID = 1L;

    private static final String message = "Invalid Username";
    
    public InvalidUsernameException(String mess){
        super(mess);
    }
    public InvalidUsernameException(){
        super(message);
    }
}
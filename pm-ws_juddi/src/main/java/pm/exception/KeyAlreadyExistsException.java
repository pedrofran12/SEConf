package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyAlreadyExistsException", propOrder = {
    "message"
})
public class KeyAlreadyExistsException extends PasswordManagerException {

    private static final long serialVersionUID = 1L;

    private static final String message = "Key already Exists";
    
    public KeyAlreadyExistsException(String mess){
        super(mess);
    }
    public KeyAlreadyExistsException(){
        super(message);
    }
}

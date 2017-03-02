package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "UnauthorizedRequestException", propOrder = {
    "message"
})
public class UnauthorizedRequestException extends PasswordManagerException {

    private static final long serialVersionUID = 1L;

    private static final String message = "Unauthorized Request!";
    
    public UnauthorizedRequestException(String mess){
        super(mess);
    }
    public UnauthorizedRequestException(){
        super(message);
    }
}

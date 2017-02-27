package pm;

import javax.jws.WebService;
import javax.crypto.*;
import java.security.*;

@WebService
public interface PasswordManager {
	//String currentBoard();

	//boolean play(int row, int column, int player);

	//int checkWinner();
	
	
	void register(Key publicKey);
	void put(Key publicKey, byte[] domain, byte[] username, byte[] password);
	byte[] get(Key publicKey, byte[] domain, byte[] username);
}

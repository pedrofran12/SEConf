package pm;

import javax.jws.WebService;

@WebService
public interface PasswordManager {
	//Map<,byte[]> password = new HashMap()<String,byte[]>;
	//String currentBoard();

	//boolean play(int row, int column, int player);

	//int checkWinner();
	
	
	void register(Key publicKey);
	void put(Key publicKey, byte[] domain, byte[] username, byte[] password);
	byte[] get(Key publicKey, byte[] domain, byte[] username);
}

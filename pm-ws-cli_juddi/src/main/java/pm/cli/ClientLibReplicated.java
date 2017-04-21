package pm.cli;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.Response;

import com.sun.xml.ws.client.ClientTransportException;

import pm.exception.cli.InsufficientResponsesException;
import pm.handler.ClientHandler;
import pm.ws.GetResponse;
import pm.ws.InvalidDomainException_Exception;
import pm.ws.InvalidKeyException_Exception;
import pm.ws.InvalidPasswordException_Exception;
import pm.ws.InvalidUsernameException_Exception;
import pm.ws.KeyAlreadyExistsException_Exception;
import pm.ws.PasswordManager;
import pm.ws.PutResponse;
import pm.ws.RegisterResponse;
import pm.ws.UnknownUsernameDomainException_Exception;

public class ClientLibReplicated {
	private static final long WAITING_TIME = 30 * 1000;
	private static final String WID_SEPARATOR = ":";
	
	private final List<PasswordManager> _pmList;
	private final int number_tolerating_faults;
	private final int tieBreaker;
	
	public ClientLibReplicated(List<PasswordManager> pmList, int nFaults) {
		_pmList = pmList;
		number_tolerating_faults = nFaults;
		tieBreaker = new SecureRandom().nextInt(Integer.MAX_VALUE);
	}
	
	// replicated register
	public void register(pm.ws.Key k) throws InsufficientResponsesException,
			InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		
		ArrayList<Response<RegisterResponse>> responsesList = new ArrayList<Response<RegisterResponse>>();
		for(PasswordManager pm : _pmList)
			responsesList.add(pm.registerAsync(k));
		
		boolean success = false;
		int numberResponses = 0;
		ExecutionException exception = null;
		long current = System.currentTimeMillis();
		while(numberResponses < 2*number_tolerating_faults + 1){
			// to see exception
			if (System.currentTimeMillis() - current > WAITING_TIME || // waiting time exceeded
					responsesList.isEmpty()) { // no more servers to communicate
				throw new InsufficientResponsesException();
			}
			
	        for(Response<RegisterResponse> r : responsesList){
	        	if(r.isDone()){
	        		try {
	                	//testar se Resposta e excepcao
						r.get();
						success = true;	
						numberResponses++;
	                }
	        		catch (ClientTransportException e) {
	        			System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	        		}
	                catch (ExecutionException e1) {
	                	if (!(e1.getCause() instanceof ClientTransportException)) {
	                		numberResponses++;
	                		exception = e1;
	                	} else {
	                		e1.printStackTrace();
	                	}
	                }
	                catch (Exception e) {
	                    System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	                }
	                responsesList.remove(r);
	                break;
	        	}
	        }
		}
		if(!success) {
			if (exception.getCause() instanceof InvalidKeyException_Exception)
				throw (InvalidKeyException_Exception) exception.getCause();
			else if (exception.getCause() instanceof KeyAlreadyExistsException_Exception)
				throw (KeyAlreadyExistsException_Exception) exception.getCause();
			else {
				exception.printStackTrace();
			}
		}
	}
	
	
	// replicated put
	public void put(pm.ws.Key key, byte[] domain, byte[] username, byte[] password, int wid)
			throws InsufficientResponsesException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception {
		put(key, domain, username, password, wid, tieBreaker);
	}
	
	public void put(pm.ws.Key key, byte[] domain, byte[] username, byte[] password, int wid, int tie)
			throws InsufficientResponsesException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception {
		
		String widForm = wid + WID_SEPARATOR + tie;
		
		ArrayList<Response<PutResponse>> responsesList = new ArrayList<Response<PutResponse>>();
		for(PasswordManager pm : _pmList){
			BindingProvider bindingProvider = (BindingProvider) pm;
			Map<String, Object> requestContext = bindingProvider.getRequestContext();
			// put token in request context
			System.out.printf("put token '%d' on request context%n", wid);
			requestContext.put(ClientHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY, widForm);
			responsesList.add(pm.putAsync(key, domain, username, password));
		}

		boolean success = false;
		int numberResponses = 0;
		ExecutionException exception = null;
		long current = System.currentTimeMillis();
		while(numberResponses < 2*number_tolerating_faults + 1){
			// to see exception
			if (System.currentTimeMillis() - current > WAITING_TIME || // waiting time exceeded
					responsesList.isEmpty()) { // no more servers to communicate
				throw new InsufficientResponsesException();
			}
			
	        for(Response<PutResponse> r : responsesList){
	        	if(r.isDone()){
	        		try {
	                	//testar se Resposta e excepcao
						r.get();
						success = true;	
						numberResponses++;
	                }
	        		catch (ClientTransportException e) {
	        			System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	        		}
	                catch (ExecutionException e1) {
	                	if (!(e1.getCause() instanceof ClientTransportException)) {
	                		numberResponses++;
	                		exception = e1;
	                	} else {
	                		e1.printStackTrace();
	                	}
	                }
	                catch (Exception e) {
	                    System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	                }
	                responsesList.remove(r);
	                break;
	        	}
	        }
		}
		if(!success) {
			if (exception.getCause() instanceof InvalidKeyException_Exception)
				throw (InvalidKeyException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidDomainException_Exception)
				throw (InvalidDomainException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidUsernameException_Exception)
				throw (InvalidUsernameException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidPasswordException_Exception)
				throw (InvalidPasswordException_Exception) exception.getCause();
			else {
				exception.printStackTrace();
			}
		}
	}
	
	
	// replicated get
	public GetResponseWrapper get(pm.ws.Key key, byte[] domain, byte[] username) throws InsufficientResponsesException,
			InvalidKeyException_Exception, InvalidDomainException_Exception,
			InvalidUsernameException_Exception, UnknownUsernameDomainException_Exception {
		
		ArrayList<Response<GetResponse>> responsesList = new ArrayList<Response<GetResponse>>();
		for(PasswordManager pm : _pmList)
			responsesList.add(pm.getAsync(key, domain, username));
		
		int numberResponses = 0;
        int latestTag = -1;
        int latestTie = Integer.MIN_VALUE;
        byte[] lastVersionContent = ("").getBytes();
        ExecutionException exception = null;
        long current = System.currentTimeMillis();
		while(numberResponses < 2*number_tolerating_faults + 1){
			// to see exception
			if (System.currentTimeMillis() - current > WAITING_TIME || // waiting time exceeded
					responsesList.isEmpty()) { // no more servers to communicate
				throw new InsufficientResponsesException();
			}
	        for(Response<GetResponse> r : responsesList){
	        	if(r.isDone()){
	                try {
	                	//testar se Resposta e excepcao
						r.get();
						numberResponses++;
		        		// access request context
		        		Map<String, Object> responseContext = r.getContext();

	                	byte[] content = r.get().getReturn().getValue();
	                    System.out.println("Asynchronous call result: " + printHexBinary(r.get().getReturn().getValue()));

	                    // get token from message context
	                    String widForm = (String) responseContext.get(ClientHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY);
	                    String[] splited = widForm.split(WID_SEPARATOR);
	                    int wid = Integer.parseInt(splited[0]);
	                    int tie = Integer.parseInt(splited[1]);
	                    System.out.printf("got token '%d' from response context%n", wid);

	                    if(wid > latestTag || (wid == latestTag && tie > latestTie)){
	                    	latestTag = wid;
	                    	latestTie = tie;
	                    	lastVersionContent = content;
	                    }
	                }
	                catch (ExecutionException e1) {
	                	if (!(e1.getCause() instanceof ClientTransportException)) {
	                		numberResponses++;
	                		exception = e1;
	                	} else {
	                		e1.printStackTrace();
	                	}
	                }
	                catch (Exception e) {
	                    System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getCause());
	                }
	                responsesList.remove(r);
	                break;
	        	}
	        }
		}
		if(latestTag==-1) {
			if (exception.getCause() instanceof InvalidKeyException_Exception)
				throw (InvalidKeyException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidDomainException_Exception)
				throw (InvalidDomainException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidUsernameException_Exception)
				throw (InvalidUsernameException_Exception) exception.getCause();
			else if (exception.getCause() instanceof UnknownUsernameDomainException_Exception)
				throw (UnknownUsernameDomainException_Exception) exception.getCause();
			else
				exception.printStackTrace();
		}
		
		return new GetResponseWrapper(lastVersionContent, latestTag, latestTie);
	}
	
	public class GetResponseWrapper {
		private final byte[] password;
		private final int wid;
		private final int tie;
		public GetResponseWrapper(byte[] p, int w, int t) {
			password = p;
			wid = w;
			tie = t;
		}
		public byte[] getPassword() {
			return password;
		}
		public int getWid() {
			return wid;
		}
		public int getTie() {
			return tie;
		}
	}
}

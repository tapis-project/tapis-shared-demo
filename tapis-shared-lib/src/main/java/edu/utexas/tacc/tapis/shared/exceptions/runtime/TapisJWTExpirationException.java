package edu.utexas.tacc.tapis.shared.exceptions.runtime;

public class TapisJWTExpirationException 
 extends TapisRuntimeException 
{
	private static final long serialVersionUID = -4517149013759206472L;
	
	public TapisJWTExpirationException(String message) {super(message);}
	public TapisJWTExpirationException(String message, Throwable cause) {super(message, cause);}
}

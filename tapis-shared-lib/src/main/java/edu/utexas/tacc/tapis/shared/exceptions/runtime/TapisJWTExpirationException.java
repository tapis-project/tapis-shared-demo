package edu.utexas.tacc.tapis.shared.exceptions.runtime;

import java.io.Serial;
/*
 * Exception thrown when errors prevent refreshing the Service JWT. Program will exit.
 */
public class TapisJWTExpirationException
 extends TapisRuntimeException 
{
	@Serial
	private static final long serialVersionUID = -4517149013759206472L;
	
	public TapisJWTExpirationException(String message) {super(message);}
	public TapisJWTExpirationException(String message, Throwable cause) {super(message, cause);}
}

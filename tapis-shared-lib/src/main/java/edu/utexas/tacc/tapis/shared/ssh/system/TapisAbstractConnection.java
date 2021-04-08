package edu.utexas.tacc.tapis.shared.ssh.system;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.jcraft.jsch.Channel;

import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.exceptions.runtime.TapisRuntimeException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.ssh.SSHConnection;
import edu.utexas.tacc.tapis.systems.client.gen.model.AuthnEnum;
import edu.utexas.tacc.tapis.systems.client.gen.model.TapisSystem;

public abstract class TapisAbstractConnection 
{
    /* **************************************************************************** */
    /*                                   Constants                                  */
    /* **************************************************************************** */
    // Local logger.
    private static final Logger _log = LoggerFactory.getLogger(TapisAbstractConnection.class);
    
    /* **************************************************************************** */
    /*                                    Fields                                    */
    /* **************************************************************************** */
    // From constructor.
    protected final TapisSystem         _system;
    
    // Cached connection.
    private SSHConnection           _conn;
    
    /* **************************************************************************** */
    /*                                Constructors                                  */
    /* **************************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* constructor:                                                                 */
    /* ---------------------------------------------------------------------------- */
    /** This constructor is used by subclasses to create new connections to the 
     * specified system on demand. 
     * 
     * @param system the target system 
     */
    protected TapisAbstractConnection(TapisSystem system)
    {
        // This should never happen.
        if (system == null) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "TapisAbstractConnection", "system");
            throw new TapisRuntimeException(msg);
        }
        
        _system = system;
    }
    
    /* ---------------------------------------------------------------------------- */
    /* constructor:                                                                 */
    /* ---------------------------------------------------------------------------- */
    /** This constructor can be used to share an existing connection to a system.
     * This is only valid if the same credentials would be used to connect as was used
     * to establish the existing connection.  If the connection is null, we revert
     * back to on-demand connection creation.
     * 
     * @param system the target system
     * @param conn an existing connection to the target system 
     */
    protected TapisAbstractConnection(TapisSystem system, SSHConnection conn)
    {
        this(system);
        _conn = conn;
    }
        
    /* **************************************************************************** */
    /*                                Public Methods                                */
    /* **************************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* getConnection:                                                               */
    /* ---------------------------------------------------------------------------- */
    /** Get a ssh connection to the system assigned to this object.  This is the usual
     * method subclasses use to access the connection to the system.
     * 
     * @return the connection object
     * @throws IOException when unable to get a connection
     * @throws TapisException invalid or missing credentials
     */
    public SSHConnection getConnection() throws IOException, TapisException
    {
        // Do we already have a connection?
        if (_conn != null) return _conn;
        
        // Create a new connection using the system's credentials.
        _conn = createNewConnection(_system);
        return _conn;
    }

    /* ---------------------------------------------------------------------------- */
    /* closeConnection:                                                             */
    /* ---------------------------------------------------------------------------- */
    /** Close the connection if it exists and reset the connection field to null.
     * This brings the object back to its origin state after construction, which
     * allows a new connection to the system to be established on demand.  This
     * method is idempotent.
     */
    public void closeConnection()
    {
        if (_conn != null) {
            _conn.closeSession();
            _conn = null;
        }
    }
    
    /* ---------------------------------------------------------------------------- */
    /* getSystem:                                                                   */
    /* ---------------------------------------------------------------------------- */
    public TapisSystem getSystem() {return _system;}

    /* ---------------------------------------------------------------------------- */
    /* createNewConnection:                                                         */
    /* ---------------------------------------------------------------------------- */
    /** Get a new ssh connection to the system using one of the supported authn 
     * connection methods.  This method does not maintain any state after it completes
     * and is typically NOT the method called by subclasses, but instead tailored for
     * use when the caller will initialize multiple objects with the same connection
     * instance.
     * 
     * It is the responsibility of the caller to correctly manage channels on the 
     * returned connection object.  When the connection object is passed on constructors
     * to subclasses of this class, then connection and channel management is handled
     * by this class.
     * 
     * @return the connection object
     * @throws IOException when unable to get a connection
     * @throws TapisException invalid or missing credentials
     */
    public static SSHConnection createNewConnection(TapisSystem system)
     throws IOException, TapisException
    {
        // Check input.
        if (system == null) {
            String msg = MsgUtils.getMsg("ALOE_NULL_PARAMETER", "createNewConnection", "system");
            throw new TapisRuntimeException(msg);
        }
        
        // Determine which constructor to use based on the system credentials.
        var cred = system.getAuthnCredential();
        if (cred == null) {
            String msg = MsgUtils.getMsg("SYSTEMS_MISSING_CREDENTIALS", 
                                         getSystemHostMessage(system),
                                         system.getTenant());
            throw new TapisException(msg);
        }
        
        // We currently only use two types of authn for target systems.
        SSHConnection conn = null;
        if (system.getDefaultAuthnMethod() == AuthnEnum.PASSWORD) 
            conn = new SSHConnection(system.getHost(), system.getPort(), 
                                     system.getEffectiveUserId(), cred.getPassword());
        else if (system.getDefaultAuthnMethod() == AuthnEnum.PKI_KEYS)
            conn = new SSHConnection(system.getHost(), system.getEffectiveUserId(), 
                                     system.getPort(), cred.getPublicKey(), cred.getPrivateKey());
        else {
            String msg = MsgUtils.getMsg("SYSTEMS_CMD_UNSUPPORTED_AUTHN_METHOD", 
                                         getSystemHostMessage(system),
                                         system.getTenant(), system.getDefaultAuthnMethod());
            throw new TapisException(msg);
        }
        
        return conn;
    }
    
    /* **************************************************************************** */
    /*                              Protected Methods                               */
    /* **************************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* getExistingConnection:                                                       */
    /* ---------------------------------------------------------------------------- */
    /** Subclasses use this method to determine if a connection exists and access it.
     * 
     * @return null or the existing connection
     */
    protected SSHConnection getExistingConnection() {return _conn;}
    
    /* ---------------------------------------------------------------------------- */
    /* closeChannel:                                                                */
    /* ---------------------------------------------------------------------------- */
    /** This method closes the channel if it's not null.  It will also close the 
     * connection if specified.  This method is idempotent.
     */
    protected void closeChannel(Channel channel, boolean closeConnection)
    {
        // Only close the channel if it exists on a connection.
        if (channel != null && _conn != null) _conn.returnChannel(channel);
        if (closeConnection) closeConnection();
    }
    
    /* ---------------------------------------------------------------------------- */
    /* getSystemHostMessage:                                                        */
    /* ---------------------------------------------------------------------------- */
    protected String getSystemHostMessage()
    {return _system.getId() + " (" + _system.getHost() + ")";}
    
    /* **************************************************************************** */
    /*                               Private Methods                                */
    /* **************************************************************************** */
    /* ---------------------------------------------------------------------------- */
    /* getSystemHostMessage:                                                        */
    /* ---------------------------------------------------------------------------- */
    private static String getSystemHostMessage(TapisSystem system)
    {return system.getId() + " (" + system.getHost() + ")";}
}
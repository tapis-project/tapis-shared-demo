package edu.utexas.tacc.tapis.shared.ssh.apache;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.commons.lang3.StringUtils;
import org.apache.sshd.client.SshClient;
import org.apache.sshd.client.config.hosts.HostConfigEntry;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.SshException;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.signature.BuiltinSignatures;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.common.util.security.bouncycastle.BouncyCastleSecurityProviderRegistrar;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.exceptions.recoverable.TapisRecoverableException;
import edu.utexas.tacc.tapis.shared.exceptions.recoverable.TapisSSHAuthException;
import edu.utexas.tacc.tapis.shared.exceptions.recoverable.TapisSSHConnectionException;
import edu.utexas.tacc.tapis.shared.exceptions.recoverable.TapisSSHTimeoutException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.utils.ThrottleMap;

/** This class abstracts the idea of an authenticated SSH connection to a host.
 * Currently, this class supports exactly one session per client instance.  This is
 * another way of saying that in Tapis, there's a 1-to-1 correspondence between
 * connections and sessions.  Apache SSH allows multiple sessions per connection,
 * where each session is authenticated with its own credentials.
 * 
 * Future enhancements might allow for a single, long-lived connection to be
 * established to commonly used hosts in which the connection would manage many
 * sessions.  This type of multiplexed connection would act like a tunnel to
 * the remote host and avoid incurring frequent connection setup overhead.  
 * 
 * Some of the code used by this class concerning PEM file parsing is based on code
 * from a public MasterCard repository with MIT license.
 * 
 * Source: https://github.com/Mastercard/client-encryption-java/blob/master/src/main/java/com/mastercard/developer/utils/EncryptionUtils.java
 *         https://stackoverflow.com/questions/7216969/getting-rsa-private-key-from-pem-base64-encoded-private-key-file/55339208#55339208
 * 
 * @author rcardone
 */
public class SSHConnection
 implements Closeable
{
    /* ********************************************************************** */
    /*                               Constants                                */
    /* ********************************************************************** */
    // Tracing.
    private static final Logger _log = LoggerFactory.getLogger(SSHConnection.class);
    
    // For logging purposes, allow the calling program to initialize the host 
    // that we are running on.  If not set, no extra logging occurs.
    private static String LOCAL_NODE_NAME; 
    
    // Throttle settings.
    private static final String THROTTLEMAP_NAME = "SSHConnectThrottleMap";
    private static final int    THROTTLE_SECONDS = 4; // Sliding window size
    private static final int    THROTTLE_LIMIT   = 8; // Max connects in window
    private static final int    CONNECT_DELAY_MS    = 4000; // Mininum delay
    private static final int    CONNECT_MAX_SKEW_MS = 8000; // Added skew maximum

    /* ********************************************************************** */
    /*                            Initializers                                */
    /* ********************************************************************** */
    // Hard code the log level for a specific package.
    static {
        // Configure apache ssh logging by interfacing directly with logback.
        var sshLogger =
           (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger("org.apache.sshd");
        if (sshLogger != null) sshLogger.setLevel(ch.qos.logback.classic.Level.WARN);//.TRACE);//ERROR); TODO
    }

    // We will use BouncyCastle for the ssh-key processing, so make sure we register the provider.
    static {
        var bcr = new BouncyCastleSecurityProviderRegistrar();
        var bc = new BouncyCastleProvider();
        Security.addProvider(new BouncyCastleProvider());
    }


    /* ********************************************************************** */
    /*                                 Enums                                  */
    /* ********************************************************************** */
    // Public enums.
    public enum AuthMethod {PUBLICKEY_AUTH, PASSWORD_AUTH}
    
    // Private enums.
    private enum ExceptionSource {CONNECT, AUTH}
    
    /* ********************************************************************** */
    /*                                Fields                                  */
    /* ********************************************************************** */
    // Map of host name to throttle entries used to control the number of launch 
    // issued to a host within a time window.
    private static final ThrottleMap _connectThrottles = initConnectThrottles();

    // Fixed at construction.
    private final String      _host;
    private final int         _port;
    private final String      _username;
    private final SSHTimeouts _timeouts;
    private final AuthMethod  _authMethod;
    
    // Optional constructor parameters.
    private String            _password;
    private String            _privateKey;
    private String            _publicKey;
    
    // Field assigned during processing.
    private SshClient         _client;
    private ClientSession     _session;
    
    /* ********************************************************************** */
    /*                            Constructors                                */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    /*
     *  Establish a password authenticated client+session with default timeouts
     */
    public SSHConnection(String host, int port, String username, String password)
     throws TapisException 
    {
        this(host, port, username, password, new SSHTimeouts());
    }

    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    /**
     *  Establish a password authenticated client+session with given timeouts
     * 
     * @param host
     * @param port
     * @param username
     * @param password
     * @param timeouts
     * @throws TapisException
     */
    public SSHConnection(String host, int port, String username, String password,
                         SSHTimeouts timeouts) 
     throws TapisException 
    {
        // Check call-specific input.
        if (password == null) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "SSHConnection", "password");
            throw new TapisException(msg);
        }
        
        // Assign fields.
        _host = host;
        _port = port > 0 ? port : 22;
        _username = username;
        _password = password;
        _timeouts = timeouts;
        _authMethod = AuthMethod.PASSWORD_AUTH;
        
        // Establish a connected and authenticated session.
        // Initialize and start a client. Use client.connect() to start a session.
        try {initSession();}
            catch (TapisException e) {
                throw e;
            }
            catch (Exception e) {
                String msg = MsgUtils.getMsg("TAPIS_SSH_CONNECT_ERROR", host, port,
                                             username, _authMethod, e.getMessage());
                throw new TapisException(msg, e);
            }
    }

    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    /**
     *  Establish a PKI authenticated client+session with default timeouts
     *
     * @param host
     * @param port
     * @param username
     * @param publicKey
     * @param privateKey
     * @throws TapisException
     */
    public SSHConnection(String host, int port, String username,
                         String publicKey, String privateKey) 
     throws TapisException 
    {
        this(host, port, username, publicKey, privateKey, new SSHTimeouts());
    }
    
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    /**
     *  Establish a PKI authenticated client+session with given timeouts
     *
     * @param host
     * @param port
     * @param username
     * @param publicKey
     * @param privateKey
     * @param timeouts
     * @throws TapisException
     */
    public SSHConnection(String host, int port, String username, String publicKey, 
                         String privateKey, SSHTimeouts timeouts) 
     throws TapisException 
    {
        // Check call-specific input.
        if (publicKey == null) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "SSHConnection", "publicKey");
            throw new TapisException(msg);
        }
        if (privateKey == null) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "SSHConnection", "privateKey");
            throw new TapisException(msg);
        }
        
        // Assign fields.
        _host = host;
        _username = username;
        _port = port > 0 ? port : 22;
        _privateKey = privateKey;
        _publicKey = publicKey;
        _timeouts = timeouts;
        _authMethod = AuthMethod.PUBLICKEY_AUTH;
        
        // Establish a connected and authenticated session.
        // Initialize and start a client. Use client.connect() to start a session.
        try {initSession();}
            catch (TapisException e) {
                throw e;
            }
            catch (Exception e) {
                String msg = MsgUtils.getMsg("TAPIS_SSH_CONNECT_ERROR", host, port,
                                             username, _authMethod, e.getMessage());
                throw new TapisException(msg, e);
            }
    }
    
    /* ********************************************************************** */
    /*                            Public Methods                              */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* getExecChannel:                                                        */
    /* ---------------------------------------------------------------------- */
    public SSHExecChannel getExecChannel()
    {
        return new SSHExecChannel(this);
    }
    
    /* ---------------------------------------------------------------------- */
    /* getSftpClient:                                                         */
    /* ---------------------------------------------------------------------- */
    public SSHSftpClient getSftpClient() throws IOException
    {
        return new SSHSftpClient(this);
    }
    
    /* ---------------------------------------------------------------------- */
    /* getScpClient:                                                          */
    /* ---------------------------------------------------------------------- */
    public SSHScpClient getScpClient() throws IOException
    {
        return new SSHScpClient(this);
    }
    
    /* ---------------------------------------------------------------------- */
    /* stop:                                                                  */
    /* ---------------------------------------------------------------------- */
    /** Close session and client if necessary without throwing exceptions.    */
    public synchronized void stop()
    {
        // Close the session immediately.
        closeSession(true);
        
        // Stop the client.
        if (_client != null) {
            _client.stop();
        }
    }
    
    /* ---------------------------------------------------------------------- */
    /* isClosed:                                                              */
    /* ---------------------------------------------------------------------- */
    public synchronized boolean isClosed()
    {
        if (_client == null  || _client.isClosed() || 
            _session == null || _session.isClosed()) 
            return true;
        return false;
    }

    /* ---------------------------------------------------------------------- */
    /* close:                                                                 */
    /* ---------------------------------------------------------------------- */
    /** Method on the Closeable interface. */
    @Override
    public void close() {stop();}
    
    /* ---------------------------------------------------------------------- */
    /* setLocalNodeName:                                                      */
    /* ---------------------------------------------------------------------- */
    public static void setLocalNodeName(String nodeName) {LOCAL_NODE_NAME = nodeName;}
    
    /* ********************************************************************** */
    /*                               Accessors                                */
    /* ********************************************************************** */
    public ClientSession getSession() {return _session;}
    public String getHost() {return _host;}
    public int getPort() {return _port;}
    public String getUsername() {return _username;}
    public SSHTimeouts getTimeouts() {return _timeouts;}
    public AuthMethod getAuthMethod() {return _authMethod;}
    
    /* ********************************************************************** */
    /*                           Protected Methods                            */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* restart:                                                               */
    /* ---------------------------------------------------------------------- */
    /** Restart a client and re-establish its session.  Typically, this method
     * is called with the caller detects that the client is stopped or the 
     * session is closed.
     * 
     * @throws TapisException
     * @throws IOException
     */
    protected synchronized void restart() throws TapisException, IOException
    {
        initSession();
    }
    
    /* ********************************************************************** */
    /*                            Private Methods                             */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* initSession:                                                           */
    /* ---------------------------------------------------------------------- */
    private void initSession() throws TapisException, IOException 
    {
        // Check input.
        if (StringUtils.isBlank(_host)) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "initSession", "host");
            throw new TapisException(msg);
        }
        if (StringUtils.isBlank(_username)) {
            String msg = MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "initSession", "username");
            throw new TapisException(msg);
        }
        
        // Throttle the rate at which we connect to this host.
        throttleLaunch(_host);
        
        // Create a new client.
        if (_client != null) stop();
        _client = SshClient.setUpDefaultClient();
        _client.setSignatureFactories(Arrays.asList(BuiltinSignatures.rsa,
                BuiltinSignatures.nistp256,
                BuiltinSignatures.nistp384,
                BuiltinSignatures.nistp521,
                BuiltinSignatures.ed25519,
                BuiltinSignatures.ed25519_cert,
                BuiltinSignatures.sk_ssh_ed25519));
        _client.start();
        var a = _client.getKeyIdentityProvider();
        var b = _client.getHostBasedAuthenticationReporter();
        var c = _client.getPublicKeyAuthenticationReporter();
        var d = _client.getCipherFactoriesNames();
        var e1 = _client.getCipherFactories();
        var f = _client.getProperties();
        var g = _client.getSignatureFactoriesNames();
        var h = _client.getSignatureFactories();

        // Connect the session.
        try {
            HostConfigEntry hostConfig = new HostConfigEntry(_host, _host, _port, _username);
            hostConfig.setIdentitiesOnly(true);
            _session = _client.connect(hostConfig)
                    .verify(_timeouts.getConnectMillis())
                    .getSession();

// TODO            // TODO
//            KeyPairResourceLoader loader = SecurityUtils.getKeyPairResourceParser();
//            try {
//                var fp = Path.of("/home/scblack/src_git/github/dev/tapis-shared-java/tapis-shared-lib/src/test/resources/edu/utexas/tacc/tapis/shared/ssh/apache/sshkeygen_ed25519");
//                var keyPairs = loader.loadKeyPairs(null, fp, null);
//                var i = 1;
//            } catch (Exception e) {}
//            // TODO

        } catch (Exception e) {
            stop();
            TapisRecoverableException rex = getRecoverable(e, ExceptionSource.CONNECT);
            if (rex == null) throw e;
            rex.state.put("hostname", _host);
            rex.state.put("username", _username);
            rex.state.put("port", String.valueOf(_port));
            rex.state.put("authMethod", _authMethod.name());
            throw rex;
        }
        if (LOCAL_NODE_NAME != null) logConnect();
        
        // Authenticate the user.
        if (_authMethod == AuthMethod.PASSWORD_AUTH) 
            _session.addPasswordIdentity(_password);
          else {
              // Initialize data for the key loader
              var keyLoader = new SSHKeyLoader(_publicKey, _privateKey, _username, _host);
              // Convert the incoming key pair into a java.security KeyPair
              // This routine attempts to detect the key type and encryption algorithm
              KeyPair keyPair = keyLoader.getKeyPair();
              // Add converted credentials to the session
              _session.addPublicKeyIdentity(keyPair);
          }
            
        // Authenticate the user.
        try {_session.auth().verify(_timeouts.getAuthenticateMillis());}
            catch (Exception e) {
                stop();
                TapisRecoverableException rex = getRecoverable(e, ExceptionSource.AUTH);
                if (rex == null) throw e;
                rex.state.put("hostname", _host);
                rex.state.put("username", _username);
                rex.state.put("port", String.valueOf(_port));
                rex.state.put("authMethod", _authMethod.name());
                throw rex;
            }
        if (LOCAL_NODE_NAME != null) logAuth();
    }

    /* ---------------------------------------------------------------------- */
    /* closeSession:                                                          */
    /* ---------------------------------------------------------------------- */
    private void closeSession(boolean immediate)
    {
        // Close the session.
        if (_session != null) { 
            if (LOCAL_NODE_NAME != null) logDisconnect();
            // Close abruptly or gracefully.
            _session.close(immediate);
            _session = null;
        }
    }

    /* ---------------------------------------------------------------------- */
    /* getRecoverable:                                                        */
    /* ---------------------------------------------------------------------- */
    /** Return a TapisRecoverableException if a recoverable condition is detected.
     * The actual exception class returned depends on the call site from where the
     * exception occurred and the error condition.
     * 
     * @param e the exception
     * @param source the call site where the exception occurred
     * @return a subclass of TapisRecoverableException or null for unrecoverable exceptions
     */
    private TapisRecoverableException getRecoverable(Exception e, ExceptionSource source)
    {
        // Let's see what ssh is trying to tell us.
        if (e instanceof SshException)
        {
            // Certain connection and authentication errors are possibly recoverable.
            int disconnectCode = ((SshException)e).getDisconnectCode();
            switch (disconnectCode) {
                // This is the list of recoverable connection and authentication errors.
                case SshConstants.SSH2_DISCONNECT_CONNECTION_LOST:
                case SshConstants.SSH2_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE:
                case SshConstants.SSH2_DISCONNECT_TOO_MANY_CONNECTIONS:
                case SshConstants.SSH2_DISCONNECT_SERVICE_NOT_AVAILABLE:
                    if (source == ExceptionSource.CONNECT) 
                        return new TapisSSHConnectionException(e.getMessage(), e, null);
                      else 
                        return new TapisSSHAuthException(e.getMessage(), e, null);
            }
        }
        
        // We try to detect other recoverable conditions by examining the error message.
        var msg = e.getMessage();
        if (msg != null) {
            if (msg.contains("timeout")) return new TapisSSHTimeoutException(e.getMessage(), e, null);
        }
        
        // Didn't identify any recoverable condition.
        return null;
    }
    
    /* ---------------------------------------------------------------------- */
    /* logConnect:                                                            */
    /* ---------------------------------------------------------------------- */
    private void logConnect()
    {
        if (!_log.isDebugEnabled()) return;
        _log.debug(MsgUtils.getMsg("TAPIS_SSH_CONNECT", LOCAL_NODE_NAME, 
                                   _username, _host, _port));
    }

    /* ---------------------------------------------------------------------- */
    /* logDisconnect:                                                         */
    /* ---------------------------------------------------------------------- */
    private void logDisconnect()
    {
        if (!_log.isDebugEnabled()) return;
        byte[] bytes = _session == null ? null : _session.getSessionId();
        String id = (bytes == null) ? null : Base64.getEncoder().encodeToString(bytes);
        _log.debug(MsgUtils.getMsg("TAPIS_SSH_DISCONNECT", LOCAL_NODE_NAME,
                                   _username, _host, _port, id));
    }

    /* ---------------------------------------------------------------------- */
    /* logAuth:                                                               */
    /* ---------------------------------------------------------------------- */
    private void logAuth()
    {
        if (!_log.isDebugEnabled()) return;
        byte[] bytes = _session == null ? null : _session.getSessionId();
        String id = (bytes == null) ? null : Base64.getEncoder().encodeToString(bytes);
        _log.debug(MsgUtils.getMsg("TAPIS_SSH_AUTH", LOCAL_NODE_NAME, _username, 
                                   _host, _port, id, _authMethod.name()));
    }
    
    /* ---------------------------------------------------------------------- */
    /* throttleLaunch:                                                        */
    /* ---------------------------------------------------------------------- */
    /** Delay launches when too many have recently taken place on a host.  This
     * works best for occasional spikes in SSH connection requests, but is less
     * effective if a large number of requests occur over an extended period. 
     * 
     * The implementation simply delays a connection attempt CONNECT_DELAY_MS +
     * random(CONNECT_MAX_SKEW_MS) milliseconds.  This approach smoothes out 
     * spikes but ultimately attempts every connection after a short delay.  
     * 
     * This approach has known limitations.  Say, for example, 1000 connection 
     * requests occur nearly at once and 8 connections are allowed in a sliding 
     * window of 4 seconds.  There will be a short delay after the first 8 connection
     * requests fill the window, but requests received while the window is closed
     * will still proceed after a short delay.  We can think of this as window 
     * spillage or overflow because even though the window is closed, more than
     * the configured maximum connections will likely be attempted soon.
     * 
     * If handling occasional spikes is not sufficient and we really need to strictly 
     * limit the number of connections within the sliding window, then we would
     * need to queue or reject overflow connections.  Queuing complicates matters 
     * because queue time might need to be bounded for some connection requests, 
     * making this facility more of a full-blown connection manager.  Until the 
     * need arises, we'll stick with the current simple approach.  
     */
    private void throttleLaunch(String host)
    {
        // Return from here if there's room in the throttle's sliding window 
    	// to connect to this host.
        if (_connectThrottles.record(host)) return;
        
        // This host needs to be throttled.
        // Calculate a randomized but short delay in milliseconds.
        var skewMs = ThreadLocalRandom.current().nextInt(CONNECT_MAX_SKEW_MS);
        skewMs += CONNECT_DELAY_MS;
        
        // Log the delay.
        if (_log.isDebugEnabled())
            _log.debug(MsgUtils.getMsg("TAPIS_SSH_DELAYED_CONNECT", skewMs, host));
        
        // Delay for the randomized period.
        try {Thread.sleep(skewMs);} catch (InterruptedException e) {}
    }
    
    /* ---------------------------------------------------------------------- */
    /* initConnectThrottles:                                                  */
    /* ---------------------------------------------------------------------- */
    private static ThrottleMap initConnectThrottles()
    {
    	return new ThrottleMap(THROTTLEMAP_NAME, THROTTLE_SECONDS, THROTTLE_LIMIT);
    }
}


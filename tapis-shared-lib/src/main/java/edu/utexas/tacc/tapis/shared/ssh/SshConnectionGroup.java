package edu.utexas.tacc.tapis.shared.ssh;

import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.exceptions.recoverable.TapisRecoverableException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.ssh.apache.SSHConnection;
import edu.utexas.tacc.tapis.shared.ssh.apache.SSHExecChannel;
import edu.utexas.tacc.tapis.shared.ssh.apache.SSHSession;
import edu.utexas.tacc.tapis.shared.ssh.apache.SSHSftpClient;
import edu.utexas.tacc.tapis.systems.client.gen.model.AuthnEnum;
import edu.utexas.tacc.tapis.systems.client.gen.model.Credential;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * This class represents all connections and sessions for a given key in the pool.
 */
final class SshConnectionGroup {
    private static final Logger log = LoggerFactory.getLogger(SshConnectionGroup.class);

    // report this group as "not ready for cleanup" for 30 mins after the last time
    // we "touched" it.  We always touch it just prior to creating a new session/connection
    // this prevents us from inadvertently cleaning up the connection group while we are
    // waiting to make a connection if there are currently no connections.
    private static final long LAST_TOUCHED_THRESHOLD = Duration.ofMinutes(30).toMillis();
    private List<SshConnectionContext> connectionContextList;
    private SshSessionPoolPolicy poolPolicy;
    private long lastTouched;
    protected SshConnectionGroup(SshSessionPoolPolicy poolPolicy) {
        connectionContextList = new ArrayList<>();
        this.poolPolicy = poolPolicy;
        lastTouched = System.currentTimeMillis();
    }

    public synchronized void touch() {
        lastTouched = System.currentTimeMillis();
    }

    /**
     * Returns information about this connection group.
     */
    public ConnectionGroupStats getGroupStats() {
        int connectionCount = 0;
        int expiredConnectionCount = 0;
        int activeConnectionCount = 0;
        int sessionCount = 0;
        int sessionsOnExpiredConnections = 0;
        int sessionsOnActiveConnections = 0;
        int sessionsOnParkedSftpConnections = 0;

        synchronized (connectionContextList) {
            for (SshConnectionContext context : connectionContextList) {
                if (context.isExpired()) {
                    expiredConnectionCount++;
                    sessionsOnExpiredConnections += context.getSessionCount();
                } else {
                    activeConnectionCount++;
                    sessionsOnActiveConnections += context.getSessionCount();
                    sessionsOnParkedSftpConnections += context.getParkedSftpSessionCount();
                }
                connectionCount++;
                sessionCount += context.getSessionCount();
            }
        }

       return new ConnectionGroupStats(connectionCount, expiredConnectionCount, activeConnectionCount,
                sessionCount, sessionsOnExpiredConnections, sessionsOnActiveConnections, sessionsOnParkedSftpConnections);
    }

    protected void cleanup() {
        synchronized (connectionContextList) {
            List<SshConnectionContext> contextsToRemove = new ArrayList<>();
            for (SshConnectionContext connectionContext : connectionContextList) {
                connectionContext.cleanup();
                // if the connection is expired, and there are no sessions left on it, close the connection,
                // and add it to the list of connections to remove from the group.
                if ((connectionContext.isExpired()) && (connectionContext.getSessionCount() == 0)) {
                    connectionContext.close();
                    contextsToRemove.add(connectionContext);
                }
            }

            // remove all connections that were identified above.
            connectionContextList.removeAll(contextsToRemove);
        }
    }

    protected boolean isReadyForCleanup() {
        // if this group is recently touched, dont report it as empty.  This will keep us
        // from cleaning it up while we are trying to create a connection on it.
        if((System.currentTimeMillis() - lastTouched) < LAST_TOUCHED_THRESHOLD) {
            return false;
        }

        return connectionContextList.isEmpty();
    }

    /**
     * Reserve a session on a connection (connection is determined internally).
     *
     * @param host
     * @param port
     * @param effectiveUserId
     * @param authnMethod
     * @param credential
     * @param sessionConstructor lambda expression describing how to construct the session
     * @param wait how long to wait for a reservation on a connection before giving up.
     * @return
     * @param <T>
     * @throws TapisException
     */
    protected  <T extends SSHSession> SshSessionHolder<T> reserveSessionOnConnection(String tenant, String host, Integer port, String effectiveUserId,
                                             AuthnEnum authnMethod, Credential credential,
                                             Class<T> clazz,
                                             Duration wait) throws TapisException {
        long startTime = System.currentTimeMillis();
        long phaseStartTime = startTime;
        long abortTime = System.currentTimeMillis() + wait.toMillis();

//        checkForPotentialDeadlocksAndLog();

        // NOTE:  It's not impossible that you could have a situation where all connections are expired,
        // but they still have active sessions.  Hopefully sessions will be relatively short lived, and one
        // of the connections will be cleaned up, and then new ones can be created.  If that becomes a problem,
        // we may have to come up with a better way to handle expired connections.
        SshSessionHolder<T> sessionHolder = null;
        synchronized (connectionContextList) {
            while (sessionHolder == null) {
                // clear out any expired connections
                log.trace(String.format("Wait for lock time: %d", System.currentTimeMillis() - phaseStartTime));

                cleanup();
                log.trace(String.format("Cleanup time: %d", System.currentTimeMillis() - phaseStartTime));
                phaseStartTime = System.currentTimeMillis();

                sessionHolder = getSession(tenant, host, port, effectiveUserId,
                            authnMethod, credential, clazz);

                log.trace(String.format("Session search time: %d", System.currentTimeMillis() - phaseStartTime));
                phaseStartTime = System.currentTimeMillis();
                if (sessionHolder == null) {
                    long waitTime = abortTime - System.currentTimeMillis();
                    if (waitTime <= 0) {
                        log.trace("Wait complete - session was " + (sessionHolder == null ? "NOT" : "") + " found");
                        break;
                    }
                }
            }
        }

        // by now we should have a session holder - if not, we can assume we timed out.
        if (sessionHolder == null) {
            log.debug(String.format("Could not get session holder: %d", System.currentTimeMillis() - phaseStartTime));
            log.trace(String.format("Total elapsed time: %d", System.currentTimeMillis() - startTime));
            String msg = MsgUtils.getMsg("SSH_POOL_RESERVE_TIMEOUT", tenant, host, port, effectiveUserId, authnMethod, wait);
            log.warn(msg);
            throw new TapisException(msg);
        }
        log.trace(String.format("Reserved session holder time: %d", System.currentTimeMillis() - phaseStartTime));
        phaseStartTime = System.currentTimeMillis();

        // I'm leaving the comment below to remind myself of this stuff if it should happen again.  I believe it
        // is fixed.  The fix is in the SftpClient.close() method.  We are now requesting a close, and confirming
        // that it happens before moving on.
        // (old_comment) Sometimes sessions fail.  The symptom is that /var/log/secure on the server side will have
        // (old_comment) a message that says - error: no more sessions.  We are already managing our sessions, so
        // (old_comment) this really shouldn't be the case, but maybe the server hasn't caught up with it's cleanup.
        // (old_comment) Perhaps due to the server being under load.  We will retry a few  times before really giving up.
        try {
            log.trace(String.format("ready to get Session time: %d", System.currentTimeMillis() - phaseStartTime));
            phaseStartTime = System.currentTimeMillis();
            sessionHolder.createSession();
            log.trace(String.format("Session established time: %d", System.currentTimeMillis() - phaseStartTime));
        } catch (Throwable th) {
            // if we are unable to create new sessions on this connection, we will expire it
            if (sessionHolder != null) {
                sessionHolder.release();
                sessionHolder.expireConnection();
            }
            String msg = MsgUtils.getMsg("SSH_POOL_UNABLE_TO_ESTABLISH_SESSION", tenant, host, port, effectiveUserId, authnMethod);
            throw new TapisException(msg, th);
        }

        log.trace(String.format("Total elapsed time: %d", System.currentTimeMillis() - startTime));

        return sessionHolder;
    }

    private <T extends SSHSession> SshSessionHolder<T> getSession(String tenant, String host, Integer port,
            String effectiveUserId, AuthnEnum authnMethod, Credential credential,
            Class<T> clazz) throws TapisException {
        SshSessionHolder<T> sessionHolder = null;
        for (SshConnectionContext sshConnectionContext : connectionContextList) {
            sessionHolder = reserveSession(sshConnectionContext, clazz);
            if (sessionHolder != null) {
                break;
            }
        }

        if ((sessionHolder == null) && (connectionContextList.size() < poolPolicy.getMaxConnectionsPerKey())) {
            SSHConnection sshConnection = createNewConnection(tenant, host, port, effectiveUserId, authnMethod, credential);
            SshConnectionContext sshConnectionContext = new SshConnectionContext(sshConnection, poolPolicy);
            connectionContextList.add(sshConnectionContext);
            sessionHolder = reserveSession(sshConnectionContext, clazz);
        }

        return sessionHolder;
    }

    private <T extends SSHSession> SshSessionHolder<T> reserveSession(SshConnectionContext connectionContext, Class<T> clazz) throws TapisException {
        if(clazz == SSHSftpClient.class) {
            return (SshSessionHolder<T>) connectionContext.reserveSftpSession();
        } else if (clazz == SSHExecChannel.class) {
            return (SshSessionHolder<T>) connectionContext.reserveSshSession();
        } else {
            // TODO: Fix this - needs real exception
            throw new RuntimeException("Unknown SSH Session type");
        }
    }

    protected SSHConnection createNewConnection(String tenant, String host, Integer port, String effectiveUserId,
                                                AuthnEnum authnMethod, Credential credential)
            throws TapisException
    {
        // check connection details for non-empty values
        if((StringUtils.isBlank(host))
                || (port == null)
                || (StringUtils.isBlank(effectiveUserId))
                || (authnMethod == null)) {
            String msg = MsgUtils.getMsg("SSH_POOL_MISSING_CONNECTION_INFORMATION",
                    tenant, host, port, effectiveUserId, authnMethod);
            log.warn(msg);
            throw new TapisException(msg);
        }

        // check credentials for non-empty values
        if(credential == null) {
            String msg = MsgUtils.getMsg("SSH_POOL_MISSING_CREDENTIALS",
                    tenant, host, port, effectiveUserId, authnMethod);
            log.warn(msg);
            throw new TapisException(msg);
        }

        // We currently only use three types of authn for target systems.
        if (authnMethod != AuthnEnum.PASSWORD &&
                authnMethod != AuthnEnum.PKI_KEYS &&
                authnMethod != AuthnEnum.TMS_KEYS)
        {
            String msg = MsgUtils.getMsg("SSH_POOL_UNSUPPORTED_AUTHN_METHOD",
                    tenant, host, port, effectiveUserId, authnMethod);
            log.warn(msg);
            throw new TapisException(msg);
        }

        // Connect.
        SSHConnection conn = null;
        try {
            if (authnMethod == AuthnEnum.PASSWORD) {
                conn = new SSHConnection(host, port,
                        effectiveUserId, credential.getPassword());
            } else if (authnMethod == AuthnEnum.PKI_KEYS) {
                conn = new SSHConnection(host, port,
                        effectiveUserId,
                        credential.getPublicKey(), credential.getPrivateKey());
            } else {
                conn = new SSHConnection(host, port,
                        effectiveUserId,
                        credential.getTmsPublicKey(), credential.getTmsPrivateKey());
    }
        } catch (TapisRecoverableException e) {
            // Handle recoverable exceptions, let non-recoverable ones through.
            // We add the systemId to all recoverable exceptions.
            e.state.put("host", host);
            e.state.put("port", port.toString());
            e.state.put("effectiveUserId", effectiveUserId);
            throw e;
        }

        // Non-null if we get here.
        return conn;
    }

    @Override
    public String toString() {
        return getDetails(false);
    }

    public String getDetails(boolean includeAll) {
        StringBuilder builder = new StringBuilder();

        synchronized (connectionContextList) {
            for (SshConnectionContext connectionContext : connectionContextList) {
                builder.append(connectionContext.getDetails(includeAll));
                builder.append(System.lineSeparator());
            }
        }

        return builder.toString();
    }

}

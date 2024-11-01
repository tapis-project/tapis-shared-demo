package edu.utexas.tacc.tapis.sharedapi.jaxrs.filters;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;

import javax.annotation.Priority;
import javax.annotation.security.PermitAll;
import javax.validation.constraints.NotNull;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.Provider;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.shared.TapisConstants;
import edu.utexas.tacc.tapis.shared.exceptions.TapisSecurityException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.parameters.TapisEnv;
import edu.utexas.tacc.tapis.shared.parameters.TapisEnv.EnvVar;
import edu.utexas.tacc.tapis.shared.security.ITenantManager;
import edu.utexas.tacc.tapis.shared.security.TenantManager;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadContext;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadContext.AccountType;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadLocal;
import edu.utexas.tacc.tapis.sharedapi.security.AuthenticatedUser;
import edu.utexas.tacc.tapis.sharedapi.security.TapisSecurityContext;
import edu.utexas.tacc.tapis.sharedapi.utils.TapisRestUtils;
import edu.utexas.tacc.tapis.tenants.client.gen.model.Site;
import edu.utexas.tacc.tapis.tenants.client.gen.model.Tenant;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureException;

/** This jax-rs filter is the main authentication mechanism for Tapis services 
 * written in Java.  This class depends on the Tapis Tenants service to acquire
 * the public keys of all tenants.  The Tenants service is accessed through the
 * TenantManager class.  The public keys are used to validate JWT signatures.
 * Additional tenant information is used to authorize tenants to act on behalf
 * of other tenants. 
 * 
 * This filter performs the following:
 * 
 *      - Reads the tapis jwt assertion header from the http request.
 *      - Determines whether the header is required and takes further action.
 *      - Extracts the tenant id from the unverified claims.
 *      - Optionally verifies the JWT signature using a tenant-specific key.
 *      - Enforces service and user token semantics.       
 *      - Extracts the user name and other values from the JWT claims.
 *      - Assigns claim values to their thread-local fields.
 *      - Assigns security related header values to their thread-local fields.
 *  
 * This class caches tenant public keys after it decodes them the first time.
 * It inspects the TenantManager's last update time to determine if the cache
 * might be stale and, if so, clears the caches. Tenant information rarely
 * changes, but the information cached in this class automatically stays in
 * sync with the TenantManager, no restarts or manual intervention required.
 *      
 * The test parameter filter is run after this filter and may override the values
 * set by this filter.
 * 
 * @author rcardone
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class JWTValidateRequestFilter 
 implements ContainerRequestFilter
{
    /* ********************************************************************** */
    /*                               Constants                                */
    /* ********************************************************************** */
    // Tracing.
    private static final Logger _log = LoggerFactory.getLogger(JWTValidateRequestFilter.class);
    
    // Header keys for jwts.
    private static final String TAPIS_JWT_HEADER     = "X-Tapis-Token";
    private static final String TAPIS_USER_HEADER    = "X-Tapis-User";
    private static final String TAPIS_HASH_HEADER    = "X-Tapis-User-Token-Hash";
    
    // Header keys for audit record tracking.
    private static final String TAPIS_TRACKING_HEADER        = "X-Tapis-Tracking-Id";
    private static final String TAPIS_PARENT_TRACKING_HEADER = "X-Tapis-Parent-Tracking-Id";
    
    // Tapis claim keys.
    private static final String CLAIM_TENANT         = "tapis/tenant_id";
    private static final String TAPIS_TENANT_HEADER  = "X-Tapis-Tenant";

	private static final String CLAIM_USERNAME       = "tapis/username";
    private static final String CLAIM_TOKEN_TYPE     = "tapis/token_type";
    private static final String CLAIM_ACCOUNT_TYPE   = "tapis/account_type";
    private static final String CLAIM_DELEGATION     = "tapis/delegation";
    private static final String CLAIM_DELEGATION_SUB = "tapis/delegation_sub";
    private static final String CLAIM_SITE           = "tapis/target_site";

    // Default message when logging claims for an expired jwt
    private static final String DEFAULT_CLAIMS_MSG = "<no claims found>";
    
    // No-auth openapi resource names.
    private static final String OPENAPI_JSON = "/openapi.json";
    private static final String OPENAPI_YAML = "/openapi.yaml";
    
    // The token types this filter expects.
    private static final String TOKEN_ACCESS = "access";
    
    /* ********************************************************************** */
    /*                                Fields                                  */
    /* ********************************************************************** */
    @Context
    private ResourceInfo resourceInfo;
    
    // Cache of tenant public keys, mapping tenant id to public key.
    // All access to this map must be limited to one thread at a time.
    private static final HashMap<String,PublicKey> _keyCache = new HashMap<>();
    
    // These fields must be filled in before the first request arrives so
    // that proper JWT authorization can be performed.  Once set these fields
    // cannot be changed.
    private static String _siteId;
    private static String _service;
    
    // This application's site object as specified by _siteId.
    private static Site    _localSite;
    private static Boolean _localOnlyService;
    
    // A real or mocked tenant manager object.
    private ITenantManager _tenantManager;
    
    /* ********************************************************************** */
    /*                            Constructors                                */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    /** This is the constructor used everywhere except for unit testing.  It
     * assumes that the real TenantManager class will have been initialized
     * by the time the first request comes through.  All request filters 
     * constructed in this manner have their _tenantManager field assigned
     * during processing.  Attempting to assign the field here causes an
     * exception because of the order in which JAX-RS does things.
     */
    public JWTValidateRequestFilter() {}
    
    /* ---------------------------------------------------------------------- */
    /* constructor:                                                           */
    /* ---------------------------------------------------------------------- */
    /** This is a unit test only constructor.  Callers are able to substitute
     * any mock tenant manager they would like by calling this constructor.
     * 
     * Attempting to put an Inject annotation on this constructor causes JAX-RS
     * to throw numerous exceptions, so it's up to the caller to integrate
     * this constructor into their test harness.
     * 
     * @param tenantManager a mock object
     */
    public JWTValidateRequestFilter(@NotNull ITenantManager tenantManager)
    {
        // Assign a mock tenant manager instance provided explicitly by the caller.
        _tenantManager = tenantManager;
    }
    
    /* ********************************************************************** */
    /*                            Public Methods                              */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* filter:                                                                */
    /* ---------------------------------------------------------------------- */
    @Override
    public void filter(ContainerRequestContext requestContext) 
    {
        // Tracing.
        if (_log.isTraceEnabled())
            _log.trace("Executing JAX-RX request filter: " + this.getClass().getSimpleName() + ".");

        // Reject all authentication required requests if our static information has
        // not been properly initialized.
        if (!initialized()) {
            // We abort the request because of improper static initialization.
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_UNINITIALIZED_FILTER", 
            		                     requestContext.getMethod(), "siteId, service");
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.INTERNAL_SERVER_ERROR).entity(msg).build());
            return;
        }

        // OPTIONS requests should not have any authentication
        if (requestContext.getMethod().equals(HttpMethod.OPTIONS)) return;

        // @PermitAll on the method takes precedence over @RolesAllowed on the class, allow all
        // requests with @PermitAll to go through
        if (resourceInfo.getResourceMethod().isAnnotationPresent(PermitAll.class)) return;

        // Skip JWT processing for non-authenticated requests.
        if (isNoAuthRequest(requestContext)) return;
        
        // ------------------------ Extract Encoded JWT ------------------------
        // Assign the default tenant manager instance that is a singleton expected 
        // to already exist.  This field is not null when a mock object is provided
        // on construction during unit testing.
        if (_tenantManager == null) _tenantManager = TenantManager.getInstance();
        
        // Initialize and check the local site on which this web application runs.
        if (getLocalSite() == null) {
            // We abort the request because of improper static initialization.
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_UNINITIALIZED_FILTER", 
            		                     requestContext.getMethod(), "localSite");
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.INTERNAL_SERVER_ERROR).entity(msg).build());
            return;
        }
        
        // Parse variables.
        String encodedJWT = null;
        
        // Extract the jwt header from the set of headers. 
        // We expect the key search to be case insensitive.
        MultivaluedMap<String, String> headers = requestContext.getHeaders();
        encodedJWT = headers.getFirst(TAPIS_JWT_HEADER);
            
        // Make sure that a JWT was provided when it is required.
        if (StringUtils.isBlank(encodedJWT)) {
            // This is an error in production, but allowed when running in test mode.
            // We let the endpoint verify that all needed parameters have been supplied.
            boolean jwtOptional = TapisEnv.getBoolean(EnvVar.TAPIS_ENVONLY_JWT_OPTIONAL);
            if (jwtOptional) return;
            
            // We abort the request because we're missing required security information.
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_MISSING_JWT_INFO", requestContext.getMethod());
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        
        // ------------------------ Read Tenant Claim --------------------------
        // Get the JWT without verifying the signature.  Decoding checks that
        // the token has not expired.
        @SuppressWarnings("rawtypes")
        Jwt unverifiedJwt = null;
        try {unverifiedJwt = decodeJwt(encodedJWT);}
        catch (Exception e) {
            // Preserve the decoder method's message.
            String msg = e.getMessage();
            _log.error(msg); // No need to log the stack trace again.
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        
        // Get the claims.
        Claims claims = null;
        try {claims = (Claims) unverifiedJwt.getBody();}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_GET_CLAIMS", unverifiedJwt);
            _log.error(msg, e);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        if (claims == null) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_NO_CLAIMS", unverifiedJwt);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        
        // Retrieve the tenant id from the claims section.
        String jwtTenant = (String)claims.get(CLAIM_TENANT);
        if (StringUtils.isBlank(jwtTenant)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_CLAIM_NOT_FOUND", unverifiedJwt, 
                                         CLAIM_TENANT);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        
        // ------------------------ Verify JWT ---------------------------------
        // Do we need to verify the JWT?
        boolean skipJWTVerify = TapisEnv.getBoolean(EnvVar.TAPIS_ENVONLY_SKIP_JWT_VERIFY);
        if (!skipJWTVerify) {
            try {
            	// Make sure the signature algorithm is not weak or "none".
            	prohibitNoAlg(claims, unverifiedJwt);
            	verifyJwt(encodedJWT, jwtTenant, true);
            }
            catch (Exception e) {
                Status status = Status.UNAUTHORIZED;
                String msg = e.getMessage();
                if (msg.startsWith("TAPIS_SECURITY_JWT_KEY_ERROR"))
                    status = Status.INTERNAL_SERVER_ERROR;
                _log.error(e.getMessage(), e);
                requestContext.abortWith(Response.status(status).entity(e.getMessage()).build());
                return;
            }
        }
        
        // ------------------------ Validate Claims ----------------------------
        // Check that the token is always an access token.
        String tokenType = (String)claims.get(CLAIM_TOKEN_TYPE);
        if (StringUtils.isBlank(tokenType) || !TOKEN_ACCESS.contentEquals(tokenType)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_CLAIM", CLAIM_TOKEN_TYPE,
                                         tokenType);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        
        // Check the account type.
        String accountTypeStr = (String)claims.get(CLAIM_ACCOUNT_TYPE);
        if (StringUtils.isBlank(accountTypeStr)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_CLAIM", CLAIM_ACCOUNT_TYPE,
                                         accountTypeStr);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        AccountType accountType = null;
        try {accountType = AccountType.valueOf(accountTypeStr);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_CLAIM", CLAIM_ACCOUNT_TYPE,
                                         accountTypeStr);
            _log.error(msg, e);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
        
        // Get the user.
        String jwtUser = (String)claims.get(CLAIM_USERNAME);
        if (StringUtils.isBlank(jwtUser)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_CLAIM", CLAIM_USERNAME, jwtUser);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return;
        }
       
        // Get the delegation information if it exists.
        String delegator = null;
        Boolean delegation = (Boolean)claims.get(CLAIM_DELEGATION);
        if (delegation != null && delegation) {
            delegator = (String)claims.get(CLAIM_DELEGATION_SUB);
            if (!TapisRestUtils.checkJWTSubjectFormat(delegator)) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_CLAIM", CLAIM_DELEGATION_SUB,
                                             delegator);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return;
            }
            
            // Get the tenant component of the user@tenant string.  The  
            // above validation call guarantees that this won't blow up.
            String delegationTenant = delegator.substring(delegator.indexOf('@') + 1);
            
            // Check that the jwt tenant is allowed to act on behalf of the delegation tenant.
            // If false returned, the called method has already modified the context to
            // abort the request, in which case we immediately return from here.
            if (!allowTenant(requestContext, jwtUser, jwtTenant, delegationTenant)) return;
        }
        
        // ------------------------ Assign Header Values -----------------------
        // Get information that may have been relayed in request headers.
        String headerUserTokenHash = headers.getFirst(TAPIS_HASH_HEADER);
        
        // These headers are only required on service tokens.
        String oboTenantId = headers.getFirst(TAPIS_TENANT_HEADER);
        String oboUser     = headers.getFirst(TAPIS_USER_HEADER);
        
        // These headers can be added by any caller for auditing purposes.
        String trackingId = headers.getFirst(TAPIS_TRACKING_HEADER);
        String parentTrackingId = headers.getFirst(TAPIS_PARENT_TRACKING_HEADER);
        
        // ------------------------ Validate Site Services ---------------------
        if (accountType == AccountType.service) {
            // The X-Tapis-User header is mandatory when a service jwt is used.
            if (StringUtils.isBlank(oboUser)) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_MISSING_HEADER", jwtUser, jwtTenant,
                                             accountType.name(), TAPIS_USER_HEADER);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return;
            }
            
            // The X-Tapis-User header is mandatory when a service jwt is used.
            if (StringUtils.isBlank(oboTenantId)) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_MISSING_HEADER", jwtUser, jwtTenant,
                                             accountType.name(), TAPIS_TENANT_HEADER);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return;
            }
            
            // Check that the jwt tenant is allowed to act on behalf of the header tenant.
            // If false returned, the called method has already modified the context to
            // abort the request, in which case we immediately return from here.
            if (!allowTenant(requestContext, jwtUser, jwtTenant, oboTenantId)) return;
            
            // Make sure the target site claim is present.
            String jwtSite = (String)claims.get(CLAIM_SITE);
            if (!validateTargetSite(requestContext, jwtSite, jwtTenant, jwtUser)) return;
            
            // ~~~~~~~~~~~~~~~~~~~~~~~~~~ TEMPORARY CODE ~~~~~~~~~~~~~~~~~~~~~~~~~~~
            // This code should be removed once the restricted service code is deployed.
            if (!temporaryRestrictedTenantCheck(requestContext, jwtUser, jwtTenant, oboTenantId))
            	return;
            // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        } else {
            // Account type is user. Reject any user tokens in the site-admin tenant. This
            // tenant is reserved for use by services only. Note that this check is not 
            // completely leak proof since several short circuiting conditions above accept
            // any token without making this check. This exposure is minor since the leak 
            // involves only globally permitted or unauthenticated requests. The vast 
            // majority of user tokens are subject to this check.
            if (jwtTenant.equals(_localSite.getSiteAdminTenantId())) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_USER_IN_ADMIN_TENANT", 
                                             jwtUser, jwtTenant, _siteId);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return;
            }
            
            // Make sure the obo headers are not present. We tolerate but ignore any site 
            // claim that may be present.
            if (StringUtils.isNotBlank(oboUser)) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_UNEXPECTED_HEADER", jwtUser, 
                                             jwtTenant, accountType.name(), TAPIS_USER_HEADER);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return;
            }
            if (StringUtils.isNotBlank(oboTenantId)) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_UNEXPECTED_HEADER", jwtUser, 
                                             jwtTenant, accountType.name(), TAPIS_TENANT_HEADER);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return;
            }
            
            // Set the on-behalf-of values to the jwt claim values with user tokens.
            oboTenantId = jwtTenant;
            oboUser     = jwtUser;
        }
        
        // Verify the site and tenant information AFTER the account-specific checking
        // has been performed. If false is returned, the called method has already modified 
        // the context to abort the request, in which case we immediately return from here.
        if (!validateSite(requestContext, jwtTenant, jwtUser)) return;

        // ------------------------ Assign Effective Values --------------------
        // Assign pertinent claims and header values to our threadlocal context.
        TapisThreadContext threadContext = TapisThreadLocal.tapisThreadContext.get();
        threadContext.setJwtTenantId(jwtTenant);             // from jwt claim, never null
        threadContext.setJwtUser(jwtUser);                   // from jwt claim, never null
        threadContext.setOboTenantId(oboTenantId);           // from jwt or header, never null
        threadContext.setOboUser(oboUser);                   // from jwt or header, never null
        threadContext.setAccountType(accountType);           // from jwt, never null
        threadContext.setDelegatorSubject(delegator);        // from jwt, can be null
        threadContext.setUserJwtHash(headerUserTokenHash);   // from header, can be null
        threadContext.setTrackingId(trackingId);              // from header, can be null
        threadContext.setParentTrackingId(parentTrackingId);  // from header, can be null
        threadContext.setSiteId(_siteId);                    // statically initialized

        // Inject the user and JWT into the security context and request context
        AuthenticatedUser requestUser = 
            new AuthenticatedUser(jwtUser, jwtTenant, accountTypeStr, 
                                  delegator, oboUser, oboTenantId, 
                                  headerUserTokenHash, _siteId, encodedJWT);
        requestContext.setSecurityContext(new TapisSecurityContext(requestUser));
    }

    /* ---------------------------------------------------------------------- */
    /* getSiteId:                                                             */
    /* ---------------------------------------------------------------------- */
    /** The site id should be set once before any requests are processed. */
    public static String getSiteId() {return _siteId;}
    
    /* ---------------------------------------------------------------------- */
    /* setSiteId:                                                             */
    /* ---------------------------------------------------------------------- */
    /** This field must be set before any request can be processed and is not
     * expected to change during program execution. 
     */
    public static void setSiteId(String siteId) 
    {
        if (_siteId == null) {
            _siteId = siteId;
            _log.info(MsgUtils.getMsg("TAPIS_SECURITY_LOCAL_SITE", _siteId));
        }
    }

    /* ---------------------------------------------------------------------- */
    /* setService:                                                            */
    /* ---------------------------------------------------------------------- */
    /** This field must be set before any request can be processed. */
    public static void setService(String service) 
    {if (_service == null) _service = service;}
    
    /* ********************************************************************** */
    /*                            Private Methods                             */
    /* ********************************************************************** */
    /* ---------------------------------------------------------------------- */
    /* decodeJwt:                                                             */
    /* ---------------------------------------------------------------------- */
    /** Decode the jwt without verifying its signature.
     * 
     * @param encodedJWT the JWT from the request header
     * @return the decoded but not verified jwt
     * @throws TapisSecurityException on error
     */
    @SuppressWarnings("rawtypes")
    private Jwt decodeJwt(String encodedJWT)
     throws TapisSecurityException
    {
        // Some defensive programming.
        if (encodedJWT == null) return null;
        
        // Lop off the signature part of the encoding so that the 
        // jjwt library can parse it without attempting validation.
        // We expect the jwt to contain exactly two periods in 
        // the following encoded format: header.body.signature
        // We need to remove the signature but leave both periods.
        String remnant = encodedJWT;
        int lastDot = encodedJWT.lastIndexOf(".");
        if (lastDot + 1 < encodedJWT.length()) // should always be true
            remnant = encodedJWT.substring(0, lastDot + 1);
        
        // Parse the header and claims. If for some reason the remnant
        // isn't of the form header.body. then parsing will fail.
        Jwt jwt;
        try {jwt = Jwts.parser().parse(remnant);}
            catch (Exception e) {
                // The decode may have detected an expired JWT.
                String msg;
                String emsg = e.getMessage();
                if (emsg != null && emsg.startsWith("JWT expired at")) {
                    // If an expired JWT and we can extract the claims then include them in the message.
                    String claimsMsg = DEFAULT_CLAIMS_MSG;
                    if (e instanceof ExpiredJwtException) {
                        var claims = ((ExpiredJwtException)e).getClaims();
                        claimsMsg = buildClaimsMsg(claims); // returns a default if claims == null
                    }
                    msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_EXPIRED", emsg, claimsMsg);
                }
                else msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_PARSE_ERROR", emsg);
                _log.error(msg, e);
                throw new TapisSecurityException(msg, e);
            }
        return jwt;
    }

    /* ---------------------------------------------------------------------- */
    /* prohibitNoAlg:                                                         */
    /* ---------------------------------------------------------------------- */
    /** This method must be called before once before verifyJwt to avoid allowing
     * attacker to constructing JWT that avoid robust signature verification by 
     * specifying weak or no algorithms.
     * 
     * @param claims the JWT's claims
     * @param unverifiedJwt the unverified JWT with header
     * @throws TapisSecurityException if the "none" algorithm is specified
     */
    @SuppressWarnings("rawtypes")
    private void prohibitNoAlg(Claims claims, Jwt unverifiedJwt)
     throws TapisSecurityException
    {
        // Get the header.
        Header<?> header = null;
        try {header = unverifiedJwt.getHeader();}   
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_GET_HEADER", buildClaimsMsg(claims));
            _log.error(msg, e);
            throw new TapisSecurityException(msg);
        }
        if (header == null) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_NO_HEADER", buildClaimsMsg(claims));
            _log.error(msg);
            throw new TapisSecurityException(msg); 
        }
        
        // Get the algorithm
        String alg = null;
        try {alg = (String) header.get("alg");}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_ALG_FORMAT", buildClaimsMsg(claims));
            _log.error(msg, e);
            throw new TapisSecurityException(msg);
        }
        
    	// Prohibit no algorithms.
    	if (StringUtils.isBlank(alg) || alg.equalsIgnoreCase("none")) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_ALG", alg, buildClaimsMsg(claims)); 
            _log.error(msg);
            throw new TapisSecurityException(msg);
    	}
    }
    
    /* ---------------------------------------------------------------------- */
    /* verifyJwt:                                                             */
    /* ---------------------------------------------------------------------- */
    /** Verify the jwt as it was received as a header value.  Signature verification
     * occurs using the specified tenant's signing key.  An exception is thrown
     * if decoding or signature verification fails.  
     * 
     * If the allowRefresh flag is set, then an attempt will be made on signature 
     * validation errors to refresh the tenants lists.  If the tenant's public
     * key has been updated, the refresh should acquire the new key.  The tenant
     * manager throttles the number of refreshes it allows in a time period, so
     * there may be a delay in getting new keys.
     * 
     * @param encodedJwt the raw jwt
     * @param tenant the tenant to verify against
     * @param allowRefresh allow the tenants list to be refreshed
     * @throws TapisSecurityException if the jwt cannot be verified 
     */
    private void verifyJwt(String encodedJwt, String tenant, boolean allowRefresh) 
     throws TapisSecurityException
    {
        // Get the public part of the signing key.
        PublicKey publicKey = getJwtPublicKey(tenant);
        
        // Verify and import the jwt data.
        @SuppressWarnings({ "unused", "rawtypes" })
        Jwt jwt = null; 
        try {jwt = Jwts.parser().setSigningKey(publicKey).parse(encodedJwt);}
            catch (SignatureException e) {
                // Signature validation could have failed because we used
                // a stale public key for this tenant.  Let's see if refreshing
                // the tenant information is possible and helpful.  No need to 
            	// recheck the algorithm since the jwt doesn't change on the 
            	// recursive call.
                if (allowRefresh && refreshTenants()) 
                    verifyJwt(encodedJwt, tenant, false); // prevent infinite recursion
                  else {
                      String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_PARSE_ERROR", e.getMessage());
                      _log.error(msg, e);
                      throw new TapisSecurityException(msg, e);
                  }
            }
            catch (Exception e) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_PARSE_ERROR", e.getMessage());
                _log.error(msg, e);
                throw new TapisSecurityException(msg, e);
            }
    }
    
    /* ---------------------------------------------------------------------- */
    /* getJwtPublicKey:                                                       */
    /* ---------------------------------------------------------------------- */
    /** Return the cached public key if it exists.  If it doesn't exist, load it
     * from the keystore, cache it, and then return it. 
     * 
     * The exceptions thrown by this method all use the TAPIS_SECURITY_JWT_KEY_ERROR
     * message.  This message is used by calling routines to distinguish between
     * server and requestor errors.
     * 
     * @param tenantId the tenant whose signature verification key is requested
     * @return the tenant's signature verification key
     * @throws TapisSecurityException on error
     */
    private PublicKey getJwtPublicKey(String tenantId)
     throws TapisSecurityException
     {
        // Get when the tenant information was last updated.
        Instant lastTenantUpdate = _tenantManager.getLastUpdateTime();
        
        // Synchronize access to the key cache across all instances of this class.
        synchronized (_keyCache) 
        {
            // ------------------- Check For Cached Key -------------------
            // See if we need to clear the cache because the tenant information has changed.
            if (lastTenantUpdate != null)  // should never be null but we check anyway
                if (Instant.now().isBefore(lastTenantUpdate)) _keyCache.clear();
                  else {
                      // Return the previously calculated public key if it exists.
                      PublicKey publicKey = _keyCache.get(tenantId);
                      if (publicKey != null) return publicKey;
                  }
            
            // ------------------- Decode New Key -------------------------
            // Get the tenant's public key as saved in the tenants table.
            Tenant tenant;
            try {tenant = _tenantManager.getTenant(tenantId);} 
                catch (Exception e) {
                    String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_KEY_ERROR", e.getMessage());
                    _log.error(msg, e);
                    throw new TapisSecurityException(msg, e);
                }
            
            // Trim prologue and epilogue if they are present.
            String encodedPublicKey = trimPublicKey(tenant.getPublicKey());
            
            // Decode the base 64 string.
            byte[] publicBytes;
            try {publicBytes = Base64.getDecoder().decode(encodedPublicKey);}
                catch (Exception e) {
                    String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_KEY_ERROR", e.getMessage());
                    _log.error(msg, e);
                    throw new TapisSecurityException(msg, e);
                }
            
            // Create the public key object from the byte array.
            PublicKey publicKey;
            try {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                publicKey = keyFactory.generatePublic(keySpec);
            }
            catch (Exception e) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_KEY_ERROR", e.getMessage());
                _log.error(msg, e);
                throw new TapisSecurityException(msg, e);
            }
        
            // Add the key to the cache before returning.
            _keyCache.put(tenantId, publicKey);
            return publicKey;
        }
     }
    
    /* ---------------------------------------------------------------------- */
    /* trimPublicKey:                                                         */
    /* ---------------------------------------------------------------------- */
    /** Remove the prologue and epilogue text if they exist from an base64 
     * encoded key string.
     * 
     * @param encodedPublicKey base64 encoded public key
     * @return trimmed base64 public key
     */
    private String trimPublicKey(String encodedPublicKey)
    {
        // This should never happen.
        if (encodedPublicKey == null) return "";
        
        // Remove prologue and epilogue if they exist.  The Tapis Tenants service
        // often stores keys with the following PEM prologue and epilogue (see
        // https://tools.ietf.org/html/rfc1421 for the specification):
        //
        //      "-----BEGIN PUBLIC KEY-----\n"
        //      "\n-----END PUBLIC KEY-----"
        //
        // In general, different messages can appear after the BEGIN and END text,
        // so stripping out the prologue and epilogue requires some care.  The  
        // approach below handles only unix-style line endings.  
        // 
        // Check for unix style prologue.
        int index = encodedPublicKey.indexOf("-\n");
        if (index > 0) encodedPublicKey = encodedPublicKey.substring(index + 2);
        
        // Check for unix style epilogue.
        index = encodedPublicKey.lastIndexOf("\n-");
        if (index > 0) encodedPublicKey = encodedPublicKey.substring(0, index);
        
        return encodedPublicKey;
    }
    
    /* ---------------------------------------------------------------------- */
    /* isNoAuthRequest:                                                       */
    /* ---------------------------------------------------------------------- */
    /** Return true if the requested uri is exempt from authentication.  These
     * request do not contain a JWT so no authentication is possible.
     * 
     * @param requestContext the request context
     * @return true is no authentication is required, false otherwise
     */
    private boolean isNoAuthRequest(ContainerRequestContext requestContext)
    {
        // Get the service-specific path, which is the path after the host:port 
        // segment and includes a leading slash.  
        String relativePath = requestContext.getUriInfo().getRequestUri().getPath();
        
        // Allow anyone to access the openapi requests.
        if (relativePath.endsWith(OPENAPI_JSON)) return true;
        if (relativePath.endsWith(OPENAPI_YAML)) return true; 
        
        // Authentication required.
        return false;
    }
    
    /* ---------------------------------------------------------------------- */
    /* allowTenant:                                                           */
    /* ---------------------------------------------------------------------- */
    /** Determine whether the tenant specified in the JWT can operate on behalf
     * of the new tenant.  This method will abort the request if the new tenant
     * is not allowed.  False is returned to immediately abort the request, true 
     * to continue request processing.
     * 
     * @param requestContext the context passed into this filter
     * @param jwtUser the user designated in the JWT
     * @param jwtTenantId the tenant designated in the JWT
     * @param newTenantId the substitute tenant
     * @return true if request processing can continue, false to abort
     */
    private boolean allowTenant(ContainerRequestContext requestContext, String jwtUser, 
                                String jwtTenantId, String newTenantId)
    {
        // Consult the jwt tenant definition for allowable tenants. 
        boolean allowedTenant;
        try {allowedTenant = TapisRestUtils.isAllowedTenant(jwtTenantId, newTenantId);}
        catch (Exception e) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_ALLOWABLE_TENANT_ERROR", 
                                         jwtUser, jwtTenantId, newTenantId);
            _log.error(msg, e);
            requestContext.abortWith(Response.status(Status.INTERNAL_SERVER_ERROR).entity(msg).build());
            return false;
        }
        
        // Can the new tenant id be used by the jwt tenant?
        if (!allowedTenant) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_TENANT_NOT_ALLOWED", 
                                         jwtUser, jwtTenantId, newTenantId);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return false;
        }
        
        // The new tenant is allowed.
        return true;
    }

    /* ---------------------------------------------------------------------- */
    /* validateTargetSite:                                                    */
    /* ---------------------------------------------------------------------- */
    /** This method validates the target site claim from service jwt (user jwt's
     * do not have that claim).  The target site must match the local site.
     * 
     * @param requestContext context used to report errors
     * @param jwtSite the tapis/target_site claim from jwt
     * @param jwtTenant non-null tenant from jwt
     * @param jwtUser non-null user from jwt
     * @return true if all checks pass, false otherwise
     */
    private boolean validateTargetSite(ContainerRequestContext requestContext,
                                       String jwtSite, String jwtTenant, String jwtUser)
    {
        // Make sure the assigned target site match the local site.
        if (StringUtils.isBlank(jwtSite)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_INVALID_CLAIM", CLAIM_SITE, jwtSite);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return false;
        }
        if (!jwtSite.equals(_siteId)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_WRONG_SITE", jwtUser, jwtTenant, jwtSite, _siteId);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return false;
        }
        
        // Success.
        return true;
    }
    
    /* ---------------------------------------------------------------------- */
    /* validateSite:                                                          */
    /* ---------------------------------------------------------------------- */
    /** Validate site, tenant and service information from the JWT and request
     * headers in the context of this web application.  If any check fails, the 
     * request context is updated with an error condition, the problem is logged  
     * and false is returned.  Success is indicated with a true result.
     * 
     * The JWT can reflect a service or user account.  No OBO or target site 
     * checks are made since those apply only to service JWTs.
     * 
     * @param requestContext context used to report errors
     * @param jwtTenant non-null tenant from jwt
     * @param jwtUser non-null user from jwt
     * @return true if all checks pass, false otherwise
     */
    private boolean validateSite(ContainerRequestContext requestContext, 
    		                     String jwtTenant, String jwtUser)
    {
    	// ----------------------- Cross-site checks -----------------------
    	// Get the site that owns the jwt's tenant.
    	String jwtTenantOwningSiteId = getTenantOwningSiteId(jwtTenant);
    	if (StringUtils.isBlank(jwtTenantOwningSiteId)) {
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_JWT_MISSING_SITE", jwtTenant);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return false;
    	}
    	
    	// Checks on inter-site requests only. 
    	if (!jwtTenantOwningSiteId.equals(_siteId)) {
    		// Make sure SK and Tokens are only referenced from the local site.
    		if (isLocalOnlyService()) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_INVALID_CROSS_SITE_SERVICE", 
                		                     jwtUser, jwtTenant, _siteId, _service);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return false;
    		}
    		
        	// If the local site is not the primary site, then the jwt owning site must be.	
        	// This prevents associate sites from communicating with each other.
    		var primarySiteId = _tenantManager.getPrimarySiteId();
        	if (!_siteId.equals(primarySiteId) && !jwtTenantOwningSiteId.equals(primarySiteId)) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_INTERSITE_COMM", 
	                                         jwtUser, jwtTenant, _siteId, jwtTenantOwningSiteId);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return false;
        	}
    	}
    	
    	// ------------------------- Service checks ----------------------
		// Check service constraints.  Note that for service JWTs, the allowable 
    	// tenants check called before this method already validates the oboTenant 
    	// as being allowed.  The checks here only validate that this service 
    	// should receive requests from the jwt tenant's owning site. 
    	//
    	// ---- First make sure the local (target) site runs this service.  This is
    	// somewhat redundant but requires no maintenance on site update.
		var localSiteServices = getLocalSite().getServices();
		if (!localSiteServices.contains(_service)) {
		    String slist = StringUtils.join(localSiteServices, ", ");
            String msg = MsgUtils.getMsg("TAPIS_SECURITY_NO_LOCAL_SERVICE", 
                                         jwtUser, jwtTenant, _service, _siteId, slist);
            _log.error(msg);
            requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
            return false;
		}

		// ---- Second make sure that if this is the primary site and the jwt owning site
		// is an associate site, then the associate site does not run the service.
		if (getLocalSite().getPrimary() && !_siteId.equals(jwtTenantOwningSiteId)) {
    		// Get the jwt tenant's owning site object.
    		var jwtTenantOwningSite = _tenantManager.getSite(jwtTenantOwningSiteId);
    		if (jwtTenantOwningSite == null) {
                String msg = MsgUtils.getMsg("TAPIS_SECURITY_UNKNOWN_SITE", 
                		                     jwtUser, jwtTenant, jwtTenantOwningSiteId);
                _log.error(msg);
                requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
                return false;
    		}
			
			// If associate site runs this service, then the service's requests 
			// are supposed to be routed there.
			var jwtTenantOwningSiteServices = jwtTenantOwningSite.getServices();
			if (jwtTenantOwningSiteServices.contains(_service)) {
				String msg = MsgUtils.getMsg("TAPIS_SECURITY_SOURCE_SITE_SERVICE", 
                                          	 jwtUser, jwtTenant, jwtTenantOwningSiteId, _service);
				_log.error(msg);
				requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
				return false;
			}
		}
    	
    	// Success.
    	return true;
    }
    
    /* ---------------------------------------------------------------------- */
    /* getTenantOwningSiteId:                                                 */
    /* ---------------------------------------------------------------------- */
    /** Get the home site of the specified tenant.
     * 
     * @param tenantId
     * @return the site id or null if none could be found
     */
    private String getTenantOwningSiteId(String tenantId)
    {
    	// Get the jwt tenant's site.
        Tenant tenant = null;
        try {tenant = _tenantManager.getTenant(tenantId);} 
            catch (Exception e) {return null;}
        if (tenant == null) return null;
        return tenant.getSiteId();
    }
    
    /* ---------------------------------------------------------------------- */
    /* getLocalSite:                                                          */
    /* ---------------------------------------------------------------------- */
    /** This method returns the site object associated with the _siteId value.
     * After the first call a cached object is returned.  A null result is 
     * returned if the site is unknown.  Race conditions on first use are 
     * harmless.
     * 
     * @return the webapp's site object or null
     */
    private Site getLocalSite()
    {
    	// Cache the object on first call. the cached object.
    	if (_localSite == null) _localSite = _tenantManager.getSite(_siteId);
    	return _localSite;
    }
    
    /* ---------------------------------------------------------------------- */
    /* isLocalOnlyService:                                                    */
    /* ---------------------------------------------------------------------- */
    /** Determine if this service can be accessed from remote sites.  Once
     * initialized the statically cached result is reused.  Race conditions 
     * on first use are harmless.
     * 
     * @return
     */
    private boolean isLocalOnlyService()
    {
    	// Initialize the static field on first use.
    	if (_localOnlyService == null) 
    		if (_service.equals(TapisConstants.SERVICE_NAME_SECURITY) ||
    			_service.equals(TapisConstants.SERVICE_NAME_TOKENS))
    			_localOnlyService = Boolean.TRUE;
    		else _localOnlyService = Boolean.FALSE;
    	return _localOnlyService;
    }
    
    /* ---------------------------------------------------------------------- */
    /* initialized:                                                           */
    /* ---------------------------------------------------------------------- */
    /** Make sure the static fields that specify the service and its site are set. 
     * 
     * @return true if all required fields are set, false otherwise
     */
    private static boolean initialized()
    {
    	// Make sure the service has initialized the static fields.
    	if (_siteId == null || _service == null) return false;
    	
    	return true;
    }
    
    /* ---------------------------------------------------------------------- */
    /* refreshTenants:                                                        */
    /* ---------------------------------------------------------------------- */
    /** Request the TenantManager to refresh its tenants information.
     * 
     * @return true if a refresh occurred, false otherwise
     */
    private boolean refreshTenants()
    {
        // Request a tenants refresh and determine if a refresh actually
        // occurred be comparing before and after timestamps.
        var beforeUpdateTime = _tenantManager.getLastUpdateTime();
        _tenantManager.refreshTenants();
        var afterUpdateTime  = _tenantManager.getLastUpdateTime();
        if (afterUpdateTime.isAfter(beforeUpdateTime)) return true;
          else return false;
    }

    /* ---------------------------------------------------------------------- */
    /* buildClaimsMsg:                                                        */
    /* ---------------------------------------------------------------------- */
    /** Construct a human-readable string from a Claims object.
     *
     * @param c  - Claims object
     * @return Message containing relevant claims (if any)
     */
    private String buildClaimsMsg(Claims c)
    {
        if (c == null) return DEFAULT_CLAIMS_MSG;
        return String.format("iss: %s sub: %s tapis/tenant_id: %s tapis/username: %s tapis/account_type: %s",
                   c.getIssuer(), c.getSubject(),
                   c.get(CLAIM_TENANT),
                   c.get(CLAIM_USERNAME),
                   c.get(CLAIM_ACCOUNT_TYPE));
    }
    
    /* ---------------------------------------------------------------------- */
    /* temporaryRestrictedTenantCheck:                                        */
    /* ---------------------------------------------------------------------- */
    /** A temporarily hardcoded check that detects requests from the 3rd party
     * dnasubway-authenticator, which are always rejected by Java services.
     * 
     * @param requestContext - the jaxrs context
     * @param jwtUser - user specified in jwt
     * @param jwtTenant - tenant specified in jwt
     * @param oboTenant - user specified in tapis header
     * @return true if request can proceed, false to reject request.
     */
    private boolean temporaryRestrictedTenantCheck(ContainerRequestContext requestContext, 
    		                 String jwtUser, String jwtTenant, String oboTenant)
    {
    	// Quickly determine if we are in the common case.
    	if (!jwtUser.startsWith("dnasubway")) return true;
    	
    	// We expect the dnasubway-authenticator service to not have any need to 
    	// communicate with any Java service, so any requests received from it 
    	// by all Java services are rejected.
        String msg = MsgUtils.getMsg("TAPIS_SECURITY_TENANT_NOT_ALLOWED", 
                                     jwtUser, jwtTenant, oboTenant);
        _log.error(msg);
        requestContext.abortWith(Response.status(Status.UNAUTHORIZED).entity(msg).build());
        return false;
    }
}

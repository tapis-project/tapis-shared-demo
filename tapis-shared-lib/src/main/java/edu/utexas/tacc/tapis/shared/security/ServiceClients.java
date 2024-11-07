package edu.utexas.tacc.tapis.shared.security;

import java.util.HashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.CacheStats;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.RemovalListener;
import com.google.common.cache.RemovalNotification;

import edu.utexas.tacc.tapis.apps.client.AppsClient;
import edu.utexas.tacc.tapis.auth.client.AuthClient;
import edu.utexas.tacc.tapis.client.shared.ITapisClient;
import edu.utexas.tacc.tapis.files.client.FilesClient;
import edu.utexas.tacc.tapis.globusproxy.client.GlobusProxyClient;
import edu.utexas.tacc.tapis.jobs.client.JobsClient;
import edu.utexas.tacc.tapis.meta.client.MetaClient;
import edu.utexas.tacc.tapis.notifications.client.NotificationsClient;
import edu.utexas.tacc.tapis.security.client.SKClient;
import edu.utexas.tacc.tapis.shared.TapisConstants;
import edu.utexas.tacc.tapis.shared.exceptions.TapisException;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.systems.client.SystemsClient;
import edu.utexas.tacc.tapis.tenants.client.TenantsClient;
import edu.utexas.tacc.tapis.tokens.client.TokensClient;

/** This class manages client instance for all the Tapis services.  Each client
 * object is initialized with the proper JWT for the tenant-specific site on 
 * which the service is configured.  In addition, each client is configured for
 * a specific user and tenant via OBO settings.
 * 
 * Cache replacement employs a least recently used (LRU) policy when the number
 * of clients reaches the maximum allowed.  In addition, each client has a TTL
 * that when expired will also cause it to be removed from the cache. The maximum 
 * cache size and TTL values are currently hardcoded.
 * 
 * This class requires the singleton instance of the ServiceContext class to have
 * been initialized prior to calls to getClient().  Note that ServiceContext 
 * initialization includes creating a ServiceJWT instance.
 * 
 * @author rcardone
 */
public class ServiceClients 
{
    /* ********************************************************************** */
	/*                               Constants                                */
	/* ********************************************************************** */
	// Tracing.
	private static final Logger _log = LoggerFactory.getLogger(ServiceClients.class);
	
	// Separator character used in keys.
	private static final String SEP = "|";
	
	// Initial map capacity.
	private static final int MAP_BUCKETS = 19;
	
	// Cache constraints.
	private static final int MAX_CLIENTS = 150;
	private static final int MAX_MINUTES = 10;
	
	// Indicator when no audit tracking ID is present.
	public static final String NOT_TRACKING = "NotTracking";

    /* ********************************************************************** */
	/*                                Fields                                  */
	/* ********************************************************************** */
	// The regex pattern used to split a cache key into its constituent parts.
	private final Pattern _keyPattern = Pattern.compile("\\" + SEP);
	
	// Mapping of service client classes to service names.  The map needs to be
	// manually updated when a new client is added.
	private final HashMap<Class<?>,String> _class2ServiceMap = initClass2ServiceMap();
	
	// Reverse of the previous map where the keys are service names and the 
	// values are the client classes.  This map does NOT have to be updated when
	// a new client is added.
	private final HashMap<String,Class<?>> _service2ClassMap = initService2ClassMap();
	
	// This is a cache of client objects that are specific to each user/tenant
	// combination.  Clients are site specific via their base URL setting.
	// The key is a concatenation of user, tenant and service.  The value is
	// the client object for a service customized for a particular user@tenant.
	private final LoadingCache<String,ITapisClient> _clientCache = initCache();

	/* ********************************************************************** */
	/*                       SingletonInitializer class                       */
	/* ********************************************************************** */
	/** Bill Pugh method of singleton initialization. */
	private static final class SingletonInitializer
	{
		private static final ServiceClients _instance = new ServiceClients(); 
	}
	
	/* ********************************************************************** */
	/*                              Constructors                              */
	/* ********************************************************************** */
	/* ---------------------------------------------------------------------- */
	/* constructor:                                                           */
	/* ---------------------------------------------------------------------- */
	private ServiceClients(){}

	/* ********************************************************************** */
	/*                             Public Methods                             */
	/* ********************************************************************** */
	/* ---------------------------------------------------------------------- */
	/* getInstance:                                                           */
	/* ---------------------------------------------------------------------- */
	public static ServiceClients getInstance() {return SingletonInitializer._instance;}

	/* ********************************************************************** */
	/*                             Public Methods                             */
	/* ********************************************************************** */
	/* ---------------------------------------------------------------------- */
	/* getClient:                                                             */
	/* ---------------------------------------------------------------------- */
	/** Return a typed service client instance.  The client class input parameter
	 * determines the return type.  Only client classes that have been mapped
	 * to service names will be recognized.
	 * 
	 * @param <T> the service's client class type 
	 * @param tenant the tenant of the service
	 * @param user the user on behalf of whom the service is being called
	 * @param cls the service's client class type
	 * @return the target service's strongly-typed client
	 * @throws RuntimeException
	 * @throws TapisException
	 * @throws ExecutionException 
	 */
	@SuppressWarnings("unchecked")
	public <T> T getClient(String user, String tenant, Class<T> cls) 
	 throws RuntimeException, TapisException, ExecutionException
	{
		return getClient(user, tenant, NOT_TRACKING, cls);
	}
	
	/* ---------------------------------------------------------------------- */
	/* getClient:                                                             */
	/* ---------------------------------------------------------------------- */
	/** Return a typed service client instance.  The client class input parameter
	 * determines the return type.  Only client classes that have been mapped
	 * to service names will be recognized.
	 * 
	 * @param <T> the service's client class type 
	 * @param tenant the tenant of the service
	 * @param user the user on behalf of whom the service is being called
	 * @param cls the service's client class type
	 * @return the target service's strongly-typed client
	 * @throws RuntimeException
	 * @throws TapisException
	 * @throws ExecutionException 
	 */
	@SuppressWarnings("unchecked")
	public <T> T getClient(String user, String tenant, String trackingId, Class<T> cls) 
	 throws RuntimeException, TapisException, ExecutionException
	{
		// Map the client class to its service name.
		String serviceName = _class2ServiceMap.get(cls);
		if (serviceName == null)
			throw new TapisException(MsgUtils.getMsg("TAPIS_UNKNOWN_CLIENT_CLASS", 
					                                 cls.getSimpleName()));
		
		// Return the typed client.
		return (T) getClient(user, tenant, trackingId, serviceName);
	}
	
	/* ---------------------------------------------------------------------- */
	/* getClient:                                                             */
	/* ---------------------------------------------------------------------- */
	/** Return an untyped service client instance configured for the specified
	 * tenant and user.  If the service is known, it determines the return type
	 * of the client.
	 * 
	 * @param user the user on behalf of whom the service is being called
	 * @param tenant the tenant of the service
	 * @param service the name of the target service
	 * @return the target service's client
	 * @throws RuntimeException
	 * @throws TapisException
	 * @throws ExecutionException 
	 */
	public ITapisClient getClient(String user, String tenant, String trackingId, String service) 
     throws RuntimeException, TapisException, ExecutionException
	{
	    // Guard against bogus input.
	    if (StringUtils.isBlank(user))
            throw new TapisException(MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "getClient", "user"));
        if (StringUtils.isBlank(tenant))
            throw new TapisException(MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "getClient", "tenant"));
        if (StringUtils.isBlank(trackingId))
            throw new TapisException(MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "getClient", "trackingId"));
        if (StringUtils.isBlank(service))
            throw new TapisException(MsgUtils.getMsg("TAPIS_NULL_PARAMETER", "getClient", "service"));
	    
        // If the jwts have been refreshed, then we need to discard all of our clients
        // since they were possibly created with an expired jwt.
        if (ServiceContext.getInstance().hasRefreshedTokens()) _clientCache.invalidateAll();
        
		// See if we already have the client.
		String key = getCacheKey(user, tenant, trackingId, service);
		return _clientCache.get(key);
	}
	
    /* ---------------------------------------------------------------------- */
    /* getClientClass:                                                        */
    /* ---------------------------------------------------------------------- */
	/** Return the client class object given a service name.
	 * 
	 * @param serviceName the service whose client class is requested
	 * @return the service's client class or null
	 */
	public Class<?> getClientClass(String serviceName)
	{
	    return _service2ClassMap.get(serviceName);
	}
	
	/* ---------------------------------------------------------------------- */
	/* removeClient:                                                          */
	/* ---------------------------------------------------------------------- */
	/** Remove the client from the cache if it exists and return it.  Return
	 * null if it doesn't exist. 
	 * 
	 * @param user the user on behalf of whom the service is being called
	 * @param tenant the client's tenant
	 * @param service the client's target service name
	 */
	public void removeClient(String user, String tenant, String trackingId, String service)
	{
		// Attempt to remove the client.  No attempt is made
		// to free any resources controlled by the client.
		String key = getCacheKey(user, tenant, trackingId, service);
		_clientCache.invalidate(key);
	}
	
    /* ---------------------------------------------------------------------- */
    /* getStats:                                                              */
    /* ---------------------------------------------------------------------- */
	/** Get cache usage information.
	 * @return the guava cache statistics
	 */
	public CacheStats getStats() {return _clientCache.stats();}
	
	/* ********************************************************************** */
	/*                            Private Methods                             */
	/* ********************************************************************** */
	/* ---------------------------------------------------------------------- */
	/* getCacheKey:                                                           */
	/* ---------------------------------------------------------------------- */
	private String getCacheKey(String user, String tenant, String trackingId, String service)
	{return user + SEP + tenant + SEP + service + SEP + trackingId;}
	
    /* ---------------------------------------------------------------------- */
    /* initCache:                                                             */
    /* ---------------------------------------------------------------------- */
	/** Create the client object cache with a limit on the maximum number of
	 * clients cached and a TTL on each client.
	 * 
	 * @return the cache
	 */
	private LoadingCache<String,ITapisClient> initCache()
	{
	    // Create the cache of string keys to service client objects.
	    LoadingCache<String,ITapisClient> cache = CacheBuilder.newBuilder()
	        .maximumSize(MAX_CLIENTS)
	        .expireAfterAccess(MAX_MINUTES, TimeUnit.MINUTES)
	        .removalListener(new TapisClientListener())
	        .recordStats()
	        .build(new CacheLoader<String, ITapisClient>() {
	             @Override
	             public ITapisClient load(String key) throws Exception {
	               return loadClient(key);
	             }
	           });
	    
	    return cache;
	}
	
    /* ---------------------------------------------------------------------- */
    /* loadClient:                                                            */
    /* ---------------------------------------------------------------------- */
    /** Return a new untyped service client instance configured for the specified
     * tenant and user.  This method is called by the loading cache on cache 
     * misses.
     * 
     * @param key the cache key for the new client
     * @return the target service's client
     * @throws RuntimeException
     * @throws TapisException
     */
    private ITapisClient loadClient(String key) 
     throws RuntimeException, TapisException
    {
        // Split the key into its 3 parts.
        String[] parts = _keyPattern.split(key);
        String user       = parts[0];
        String tenant     = parts[1];
        String service    = parts[2];
        String trackingId = parts[3];
        
        // Create a new client for this service/tenant combination.
        var router = ServiceContext.getInstance().getRouter(tenant, service);
        
        // Get the client.
        ITapisClient client = null;
        switch (service)
        {
            case TapisConstants.SERVICE_NAME_APPS: {
                client = new AppsClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_JOBS: {
                client = new JobsClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_SECURITY: {
                client = new SKClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_SYSTEMS: {
                client = new SystemsClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }
            
            case TapisConstants.SERVICE_NAME_AUTHN: {
                client = new AuthClient(router.getServiceBaseUrl());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_TENANTS: {
                client = new TenantsClient(router.getServiceBaseUrl());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_TOKENS: {
                client = new TokensClient(router.getServiceBaseUrl());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_META: {
                client = new MetaClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }   
                
            case TapisConstants.SERVICE_NAME_FILES: {
                client = new FilesClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }
                
            case TapisConstants.SERVICE_NAME_NOTIFICATIONS: {
                client = new NotificationsClient(router.getServiceBaseUrl(), router.getAccessJWT());
                break;
            }

            case TapisConstants.SERVICE_NAME_GLOBUSPROXY: {
              client = new GlobusProxyClient(router.getServiceBaseUrl(), router.getAccessJWT());
              break;
            }

          default:
        }
        
        // Make sure we found the client.
        if (client == null) 
            throw new TapisException(MsgUtils.getMsg("TAPIS_CLIENT_NOT_FOUND", service, tenant, user));
        
        // Assign required headers.
        client.addDefaultHeader("X-Tapis-User", user);
        client.addDefaultHeader("X-Tapis-Tenant", tenant);
        client.addDefaultHeader("Content-Type", "application/json");
        
        // Add the optional tracking ID only on clients that do tracking
        // and only when an actual tracking ID is present. 
        if (!trackingId.equals(NOT_TRACKING) && (client instanceof FilesClient))
        	client.addDefaultHeader("X-Tapis-Tracking-ID", trackingId);
        
        // Return the client.
        return client;
    }
    
	/* ---------------------------------------------------------------------- */
	/* initClass2ServiceMap:                                                  */
	/* ---------------------------------------------------------------------- */
	/** Return the mapping of service client classes to service names.
	 * 
	 * Make sure to add new clients to this map as they become available.
	 * 
	 * @return map of client classes to service names
	 */
	private HashMap<Class<?>,String> initClass2ServiceMap()
	{
		var map = new HashMap<Class<?>,String>(MAP_BUCKETS);
		map.put(AppsClient.class, TapisConstants.SERVICE_NAME_APPS);
		map.put(SKClient.class, TapisConstants.SERVICE_NAME_SECURITY);
		map.put(SystemsClient.class, TapisConstants.SERVICE_NAME_SYSTEMS);
		map.put(AuthClient.class, TapisConstants.SERVICE_NAME_AUTHN);
		map.put(TenantsClient.class, TapisConstants.SERVICE_NAME_TENANTS);
		map.put(TokensClient.class, TapisConstants.SERVICE_NAME_TOKENS);
		map.put(MetaClient.class, TapisConstants.SERVICE_NAME_META);
		map.put(FilesClient.class, TapisConstants.SERVICE_NAME_FILES);
		map.put(JobsClient.class, TapisConstants.SERVICE_NAME_JOBS);
		map.put(NotificationsClient.class, TapisConstants.SERVICE_NAME_NOTIFICATIONS);
        map.put(GlobusProxyClient.class, TapisConstants.SERVICE_NAME_GLOBUSPROXY);

		return map;
	}
	
    /* ---------------------------------------------------------------------- */
    /* initService2ClassMap:                                                  */
    /* ---------------------------------------------------------------------- */
    /** Return the mapping of service names to client classes based on the
     * reverse mapping that must already have been initialized.
     * 
     * @return map of service names to client classes
     */
	private HashMap<String,Class<?>> initService2ClassMap()
	{
	    var map = new HashMap<String,Class<?>>(MAP_BUCKETS);
	    for (var entry : _class2ServiceMap.entrySet()) 
	        map.put(entry.getValue(), entry.getKey());
	    
	    return map;
	}
	
    /* ********************************************************************** */
    /*                        TapisClientListener Class                       */
    /* ********************************************************************** */
	public class TapisClientListener 
	  implements RemovalListener<String,ITapisClient>
	{
        @Override
        public void onRemoval(RemovalNotification<String, ITapisClient> notification) 
        {
            ITapisClient clt = notification.getValue();
            if (clt == null) return;
            
            // Trace this callback method.
            if (_log.isDebugEnabled()) 
                _log.debug(MsgUtils.getMsg("TAPIS_CLIENT_UNCACHED", clt.getClass().getSimpleName()));
            
            // Each client has its own close method.
            clt.close();
        }
	}
}

package edu.utexas.tacc.tapis.sharedapi.jaxrs.filters;

import javax.annotation.Priority;
import java.util.List;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import edu.utexas.tacc.tapis.search.SearchUtils;
import edu.utexas.tacc.tapis.shared.TapisConstants;
import edu.utexas.tacc.tapis.shared.i18n.MsgUtils;
import edu.utexas.tacc.tapis.shared.threadlocal.SearchParameters;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadContext;
import edu.utexas.tacc.tapis.shared.threadlocal.TapisThreadLocal;

/*
 *  jax-rs filter to intercept various search, sort and filter query parameters and set values in the thread context.
 *  Parameters:
 *    search - String indicating search conditions to use when retrieving results
 *    limit - Integer indicating maximum number of results to be included, -1 for unlimited
 *    orderBy - e.g. orderBy=owner(asc), orderBy=created(desc)
 *    skip - number of results to skip
 *    startAfter - e.g. systems?limit=10&orderBy=id(asc)&startAfter=101
 *    computeTotal - Boolean indicating if total count should be computed. Default is false.
 *    filter - String indicating which attributes (i.e. fields) to include when retrieving results
 */
@Provider
@Priority(TapisConstants.JAXRS_FILTER_PRIORITY_AFTER_AUTHENTICATION)
public class QueryParametersRequestFilter implements ContainerRequestFilter
{
  /* ********************************************************************** */
  /*                               Constants                                */
  /* ********************************************************************** */
  // Tracing.
  private static final Logger _log = LoggerFactory.getLogger(QueryParametersRequestFilter.class);

  // Query parameter names
  private static final String PARM_SEARCH = "search";
  private static final String PARM_LIMIT = "limit";
  private static final String PARM_ORDERBY = "orderBy";
  private static final String PARM_SKIP = "skip";
  private static final String PARM_STARTAFTER = "startAfter";
  private static final String PARM_COMPUTETOTAL = "computeTotal";
  private static final String PARM_SELECT = "select";

  /* ********************************************************************** */
  /*                            Public Methods                              */
  /* ********************************************************************** */
  /* ---------------------------------------------------------------------- */
  /* filter:                                                                */
  /* ---------------------------------------------------------------------- */
  @Override
  public void filter(ContainerRequestContext requestContext)
  {
    // Retrieve all query parameters. If none we are done.
    //   and since there is a decent chance the request does not have any search/select parameters also check for that.
    MultivaluedMap<String, String> queryParameters = requestContext.getUriInfo().getQueryParameters();
    if (queryParameters == null || queryParameters.isEmpty() || !hasSearchParms(queryParameters)) return;

    // Tracing.
    if (_log.isTraceEnabled())
      _log.trace("Executing JAX-RX request filter: " + this.getClass().getSimpleName() + ".");

    // Get thread context
    TapisThreadContext threadContext = TapisThreadLocal.tapisThreadContext.get();

    // Set default sort and paginate options
    SearchParameters searchParms = new SearchParameters();
    threadContext.setSearchParameters(searchParms);

    // Look for and extract computeTotal query parameter.
    // Common checks for query parameters
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_COMPUTETOTAL)) { return; }
    String parmValueComputeTotal = getQueryParm(queryParameters, PARM_COMPUTETOTAL);
    if (!StringUtils.isBlank(parmValueComputeTotal))
    {
      // Provided parameter is valid. Set as boolean
      if ("true".equalsIgnoreCase(parmValueComputeTotal)) searchParms.setComputeTotal(true);
      else if ("false".equalsIgnoreCase(parmValueComputeTotal)) searchParms.setComputeTotal(false);
      else
      {
        String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_NOTBOOL", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                threadContext.getOboTenantId(), threadContext.getOboUser(), PARM_COMPUTETOTAL, parmValueComputeTotal);
        _log.warn(msg);
      }
    }

    // Look for and extract select query parameter.
    // This parameter is used to select which result fields are included in a response.
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_SELECT)) { return; }
    String parmValueSelect = getQueryParm(queryParameters, PARM_SELECT);
    // Extract and validate the fields.
    try
    {
      List<String> selectList = SearchUtils.getValueList(parmValueSelect);
      searchParms.setSelectList(selectList);
    }
    catch (Exception e)
    {
      String msg = MsgUtils.getMsg("SELECT_LIST_ERROR", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
              threadContext.getOboTenantId(), threadContext.getOboUser(), parmValueSelect, e.getMessage());
      _log.error(msg, e);
      requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
      return;
    }

    // Look for and extract search query parameter.
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_SEARCH)) { return; }
    String parmValueSearch = getQueryParm(queryParameters, PARM_SEARCH);
    // Extract the search conditions and validate their form. Back end will handle translating LIKE wildcard
    //   characters (* and !) and dealing with special characters in values.
    try
    {
      List<String> searchList = SearchUtils.extractAndValidateSearchList(parmValueSearch);
      searchParms.setSearchList(searchList);
    }
    catch (Exception e)
    {
      String msg = MsgUtils.getMsg("SEARCH_LIST_ERROR", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                                   threadContext.getOboTenantId(), threadContext.getOboUser(), e.getMessage());
      _log.error(msg, e);
      requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
      return;
    }

    // Look for and extract limit query parameter.
    // SearchParameters initialized limit to null so users of this class can determine if value is set on incoming request.
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_LIMIT)) { return; }
    String parmValueLimit = getQueryParm(queryParameters, PARM_LIMIT);
    if (!StringUtils.isBlank(parmValueLimit))
    {
      int limit;
      // Check that it is an integer
      try { limit = Integer.parseInt(parmValueLimit); }
      catch (NumberFormatException e)
      {
        String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_NOTINT", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                threadContext.getOboTenantId(), threadContext.getOboUser(), PARM_LIMIT, parmValueLimit);
        _log.error(msg);
        requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
        return;
      }
      searchParms.setLimit(limit);
    }

    // Look for and extract orderBy query parameter.
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_ORDERBY)) { return; }
    String parmValueOrderBy = getQueryParm(queryParameters, PARM_ORDERBY);
    if (!StringUtils.isBlank(parmValueOrderBy))
    {
      // Only do the split once and pass it in to the utility methods
      var items = SearchUtils.getValueList(parmValueOrderBy);
      // Validate and process orderBy which must be a comma separated list where each item has
      //   the form <col_name>(<dir>) where (<dir>) is optional and <dir> = "asc" or "desc"
      String errMsg = SearchUtils.checkOrderByQueryParam(parmValueOrderBy, items);
      if (errMsg != null)
      {
        String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_ORDERBY_ERROR", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                                     threadContext.getOboTenantId(), threadContext.getOboUser(), errMsg);
        _log.error(msg);
        requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
        return;
      }
      searchParms.setOrderByList(SearchUtils.buildOrderByList(parmValueOrderBy, items));
      searchParms.setOrderBy(parmValueOrderBy);
    }

    // Look for and extract skip query parameter.
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_SKIP)) { return; }
    String parmValueSkip = getQueryParm(queryParameters, PARM_SKIP);
    if (!StringUtils.isBlank(parmValueSkip))
    {
      int skip;
      // Check that it is an integer
      try { skip = Integer.parseInt(parmValueSkip); }
      catch (NumberFormatException e)
      {
        String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_NOTINT", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
                threadContext.getOboTenantId(), threadContext.getOboUser(), PARM_SKIP, parmValueSkip);
        _log.error(msg);
        requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
        return;
      }
      searchParms.setSkip(skip);
    }

    // Look for and extract startAfter query parameter.
    if (invalidParm(threadContext, requestContext, queryParameters, PARM_STARTAFTER)) { return; }
    String parmValueStartAfter = getQueryParm(queryParameters, PARM_STARTAFTER);
    if (!StringUtils.isBlank(parmValueStartAfter)) searchParms.setStartAfter(parmValueStartAfter);

    // Check constraints
    // Specifying startAfter without orderBy is an invalid combination
    if (!StringUtils.isBlank(searchParms.getStartAfter()) && searchParms.getOrderByList().isEmpty())
    {
      String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_INVALID_PAIR1", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
              threadContext.getOboTenantId(), threadContext.getOboUser(), PARM_STARTAFTER, PARM_ORDERBY);
      _log.error(msg);
      requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
      return;
    }
    // Specifying startAfter and skip is an invalid combination
    if (!StringUtils.isBlank(searchParms.getStartAfter()) && !StringUtils.isBlank(parmValueSkip))
    {
      String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_INVALID_PAIR2", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
              threadContext.getOboTenantId(), threadContext.getOboUser(), PARM_STARTAFTER, PARM_SKIP);
      _log.error(msg);
      requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
      return;
    }

    // Update parameter set in thread context
    threadContext.setSearchParameters(searchParms);
  }

  /* ********************************************************************** */
  /*                            Private Methods                             */
  /* ********************************************************************** */

  /**
   * Check for presence of search/select query parameters.
   * @return true if present else false
   */
  private static boolean hasSearchParms(MultivaluedMap<String, String> queryParameters)
  {
    return queryParameters.containsKey(PARM_SEARCH) ||
            queryParameters.containsKey(PARM_LIMIT) ||
            queryParameters.containsKey(PARM_ORDERBY) ||
            queryParameters.containsKey(PARM_SKIP) ||
            queryParameters.containsKey(PARM_STARTAFTER) ||
            queryParameters.containsKey(PARM_COMPUTETOTAL) ||
            queryParameters.containsKey(PARM_SELECT);
  }

  /**
   * Common checks for query parameters
   *   - Check that if parameter is present there is only one value
   * @param requestContext - context containing parameters
   * @param parmName - parameter to check
   * @return true if invalid, false if valid
   */
  private static boolean invalidParm(TapisThreadContext threadContext, ContainerRequestContext requestContext,
                                     MultivaluedMap<String, String> queryParameters, String parmName)
  {
    // Check that it is a single value
    if (queryParameters.containsKey(parmName) && queryParameters.get(parmName).size() != 1)
    {
      String msg = MsgUtils.getMsg("TAPIS_QUERY_PARAM_MULTIPLE", threadContext.getJwtTenantId(), threadContext.getJwtUser(),
              threadContext.getOboTenantId(), threadContext.getOboUser(), parmName);
      _log.error(msg);
      requestContext.abortWith(Response.status(Response.Status.BAD_REQUEST).entity(msg).build());
      return true;
    }
    return false;
  }

  /**
   * Get query parameter if present
   * @param queryParameters - parameters from request context
   * @param parmName - parameter to retrieve
   * @return string value of parameter or null if parameter not present
   */
  private static String getQueryParm(MultivaluedMap<String, String> queryParameters, String parmName)
  {
    String parmValue = null;
    if (queryParameters.containsKey(parmName))
    {
      parmValue = queryParameters.get(parmName).get(0);
      _log.debug("Found query parameter. Name: " + parmName + " Value: " + parmValue);
    }
    return parmValue;
  }
}

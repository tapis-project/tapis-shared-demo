package edu.utexas.tacc.tapis.shared.utils;

import com.google.gson.Gson;

import edu.utexas.tacc.tapis.shared.TapisConstants;

/** This file contains utility methods that assist in writing and managing audit logs.
 * 
 * @author rcardone
 */
public final class AuditUtils 
{
	/* **************************************************************************** */
	/*                                   Constants                                  */
	/* **************************************************************************** */
	// Reuse the gson object.
	private static final Gson _gson = TapisGsonUtils.getGson();

	// Audit logger name
	public static final String LOGGER_NAME = "audit";

	// Audit null indicator.
	public static final String AUDIT_EMPTY = "";
	
	// -------- Service component names.
    public static final String AUDIT_JOBSAPI = "jobsapi";
    public static final String AUDIT_JOBSWORKER = "jobsworker";
    public static final String AUDIT_FILESAPI = "filesapi";
    public static final String AUDIT_FILESWORKER = "filesworker";
    
    // -------- Tracking ID prefixes.
    public static final String TRACKING_PREFIX_JOB_UUID = "jobs.";
    public static final String TRACKING_PREFIX_FILES = "files."; 
    public static final String TRACKING_PREFIX_PORTALS_UUID = "portals.";
    
    // -------- Auditable action names.
    public enum AUDIT_ACTION {
    	// Audit actions with their display names that get logged.
	// Note that some of these do not begin with ACTION_ so we may easily convert between this type and types in tapis-files.
    	LINUXOP("linuxop"), // Might be used if new Linux operation is introduced and this shared code has not been updated.
        ACTION_CHGRP("chgrp"),
        ACTION_CHMOD("chmod"),
        ACTION_CHOWN("chown"),
        ACTION_COPY("copy"),
        ACTION_DELETE("delete"),
        ACTION_MOVE("move"),
        ACTION_SETFACL("setfacl"),
        ACTION_UPLOAD("upload"),
        ACTION_MKDIR("mkdir"),
        ACTION_TRANSFER("transfer"),
        ACTION_SCP_COPY("scp-copy");
    	
    	// Fields, constructor and methods.
    	private String _displayName;
    	AUDIT_ACTION(String displaName){_displayName = displaName;}
    	@Override
    	public String toString() {return _displayName;}
    }

	/* **************************************************************************** */
	/*                                Public Methods                                */
	/* **************************************************************************** */
	/* ---------------------------------------------------------------------------- */
	/* auditMsg:                                                                    */
	/* ---------------------------------------------------------------------------- */
	/** Wrapper for actual auditMsg method that services all possible parameters.  
	 * This method assigns the jwt and obo fields null, which is useful in processes 
	 * that don't expose a REST interface and, therefore, don't have JWTs. 
	 */
	public static String auditMsg(String component,
								  String action,
								  String targetSystemId,
		                          String targetSystemType,
		                          String targetHost,
		                          String targetPath,
		                          String sourceSystemId,
		                          String sourceSystemType,
		                          String sourceHost,
		                          String sourcePath,
		                          String trackingId,
		                          String parentTrackingId,
		                          String data)
	{
		return auditMsg(component, null, null, null, null, action,
			          	targetSystemId, targetSystemType, targetHost, targetPath,
			          	sourceSystemId, sourceSystemType, sourceHost, sourcePath,
			          	trackingId, parentTrackingId, data);
	}

	/* ---------------------------------------------------------------------------- */
	/* auditMsg:                                                                    */
	/* ---------------------------------------------------------------------------- */
	/** Collect all audit values into a single object. 
	 * 
	 * @param component - the component of the service issuing the call (ex: jobsapi, filesworker)
	 * @param jwtTenant - the REST request's jwt tenant
	 * @param jwtUser - the REST request's jwt user
	 * @param oboTenant - the REST request's obo tenant 
	 * @param oboUser - the REST request's obo user
	 * @param action - the action being executed
	 * @param targetSystemId - target system id
	 * @param targetSystemType - target system type
	 * @param targetHost - target host
	 * @param targetPath - target path
	 * @param sourceSystemId - source system id
	 * @param sourceSystemType - source system type
	 * @param sourceHost - source host
	 * @param sourcePath - source path
	 * @param trackingId - current tracking id
	 * @param parentTrackingId - previous tracking id
	 * @param data - arbitrary json data
	 * @return a json string representation of all inputs
	 */
	public static String auditMsg(String component,
		   			              String jwtTenant,
		   			              String jwtUser,
		   			              String oboTenant,
		   			              String oboUser,
		  						  String action,
		                          String targetSystemId,
		                          String targetSystemType,
		                          String targetHost,
		                          String targetPath,
		                          String sourceSystemId,
		                          String sourceSystemType,
		                          String sourceHost,
		                          String sourcePath,
		                          String trackingId,
		                          String parentTrackingId,
		                          String data)
	{
		// Package the inputs.
		var a = new AuditData();
		a.component = component;
		a.jwtTenant = jwtTenant;
		a.jwtUser = jwtUser;
		a.oboTenant = oboTenant;
		a.oboUser = oboUser;
		a.action = action;
		a.targetSystemId = targetSystemId;
		a.targetSystemType = targetSystemType;
		a.targetHost = targetHost;
		a.targetPath = targetPath;
		a.sourceSystemId = sourceSystemId;
		a.sourceSystemType = sourceSystemType;
		a.sourceHost = sourceHost;
		a.sourcePath = sourcePath;
		a.trackingId = trackingId;
		a.parentTrackingId = parentTrackingId;
		a.data = data;
	  
		// Return a json string.
		return auditMsg(a);
	}

	/* ---------------------------------------------------------------------------- */
	/* auditMsg:                                                                    */
	/* ---------------------------------------------------------------------------- */
	/** Write the complete audit message JSON object to string. 
	 * 
	 * @param a - the packaged audit values that may contain null values
	 * @return a json string representation of all inputs
	 */
	public static String auditMsg(AuditData a)
	{
		// Prevent null from entering the database.
		if (a.component == null) a.component = AUDIT_EMPTY;
		if (a.jwtTenant == null) a.jwtTenant = AUDIT_EMPTY;
		if (a.jwtUser == null) a.jwtUser = AUDIT_EMPTY;
		if (a.oboTenant == null) a.oboTenant = AUDIT_EMPTY;
		if (a.oboUser == null) a.oboUser = AUDIT_EMPTY;
		if (a.action == null) a.action = AUDIT_EMPTY;
		if (a.targetSystemId == null) a.targetSystemId = AUDIT_EMPTY;
		if (a.targetSystemType == null) a.targetSystemType = AUDIT_EMPTY;
		if (a.targetHost == null) a.targetHost = AUDIT_EMPTY;
		if (a.targetPath == null) a.targetPath = AUDIT_EMPTY;
		if (a.sourceSystemId == null) a.sourceSystemId = AUDIT_EMPTY;
		if (a.sourceSystemType == null) a.sourceSystemType = AUDIT_EMPTY;
		if (a.sourceHost == null) a.sourceHost = AUDIT_EMPTY;
		if (a.sourcePath == null) a.sourcePath = AUDIT_EMPTY;
		if (a.trackingId == null) a.trackingId = AUDIT_EMPTY;
		if (a.parentTrackingId == null) a.parentTrackingId = AUDIT_EMPTY;
		if (a.data == null) a.data = TapisConstants.EMPTY_JSON;

		// Return a json string.
		return _gson.toJson(a);
	}
	
	/* **************************************************************************** */
	/*                                Nested Classes                                */
	/* **************************************************************************** */
	/** Simple container class for audit values. */
	public static final class AuditData {
		public String component;
		public String jwtTenant;
		public String jwtUser;
		public String oboTenant;
		public String oboUser;
		public String action;
		public String targetSystemId;
		public String targetSystemType;
		public String targetHost;
		public String targetPath;
		public String sourceSystemId;
		public String sourceSystemType;
		public String sourceHost;
		public String sourcePath;
		public String trackingId;
		public String parentTrackingId;
		public String data;
	}
}

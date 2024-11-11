package edu.utexas.tacc.tapis.shared.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.annotations.Test;

import edu.utexas.tacc.tapis.shared.utils.AuditUtils.AuditData;

@Test(groups={"unit"})
public class AuditUtilsTest
{
	private static final Logger _audit = LoggerFactory.getLogger("audit");
	
	@Test(enabled=true)
	public void test1() 
	{
		var auditData = new AuditData();
		auditData.component = AuditUtils.AUDIT_JOBSWORKER;
		auditData.action = AuditUtils.AUDIT_ACTION.ACTION_MKDIR.toString();
		auditData.trackingId = "f36073ff-acec-4f7b-9fbd-957dbe77f233-007";

    	auditData.targetSystemId = "system1";
    	auditData.targetPath = "/jobs/f36073ff-acec-4f7b-9fbd-957dbe77f233-007";
    	auditData.targetHost = "host.tacc.utexas.edu";
    	auditData.targetSystemType = "LINUX";
    	_audit.info(AuditUtils.auditMsg(auditData));
	}
}

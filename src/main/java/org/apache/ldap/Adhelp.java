package org.apache.ldap;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;

import javax.naming.directory.Attribute;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.adldap.LdapApi;
import org.apache.adldap.LdapClient;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Servlet implementation class Adhelp
 */
public class Adhelp extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String ldapURL = "";
	private static String bindDn= "";
	private static String bindPw= "";
	private static String baseDn= "";

    /**
     * Default constructor. 
     */
    public Adhelp() {
        // TODO Auto-generated constructor stub
    	baseDn = "OU=INTERNAL,dc=hdpusr,dc=senia,dc=org";
		bindDn = "cn=ldapsearch,ou=internal,dc=hdpusr,dc=senia,dc=org";
		bindPw = "";
		ldapURL = "ldaps://seniadc1.senia.org:3269";

    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		if (request.getParameter("json") != null) {
			String reqtype = request.getParameter("type");
			String attrtype = request.getParameter("attrType");
			if (reqtype.equalsIgnoreCase("user")) {
				String samAccountName = null;
				LdapClient ldpClient = new LdapClient(baseDn, bindDn, bindPw, ldapURL);
				LdapApi api = new LdapApi();
				System.out.println("attrype: " + attrtype);
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					samAccountName = request.getParameter("id");
				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					samAccountName = api.getSamAccountNameFromCN(ldpClient, baseDn, cn);
				}
				Map<String, Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
				JSONObject obj = new JSONObject();
				obj.put("displayName", api.getDisplayName(results));
				obj.put("cn", api.getCN(results));
				obj.put("dn", api.getDN(results));
				String manager = api.getSamAccountName(api.getUserDNAttrs(ldpClient, baseDn, api.getManager(results)));
				if (manager != null) {
					obj.put("manager", "type=user&attrType=samAccountName&id=" + manager);
				}
				obj.put("userPrincipalName", api.getUPN(results));
				obj.put("phone", api.getPhoneNumber(results));
				obj.put("email", api.getUserMail(results));
				obj.put("description", api.getDescription(results));
				obj.put("location", api.getLocation(results));
				obj.put("state", api.getSt(results));
				obj.put("country", api.getCountry(results));
				obj.put("whenChanged", api.getWhenChanged(results));
				obj.put("whenCreated", api.getWhenCreated(results));
				obj.put("uSNCreated", api.getUSNCreated(results));
				obj.put("uSNChanged", api.getUSNChanged(results));
				obj.put("objectGUID", api.getObjectGuid(results));
				obj.put("createTimeStamp", api.getCreateTimeStamp(results));
				obj.put("modifyTimeStamp", api.getModifyTimeStamp(results));
				obj.put("lastLogonTimeStamp", api.getLastLogonTimeStamp(results));
				obj.put("pwdLastSet", api.getPwdLastSet(results));
				obj.put("lockoutTime", api.getLockOutTime(results));
				obj.put("badPwdCount", api.getBadPwdCount(results));
				obj.put("badPasswordTime", api.getBadPwdTime(results));
				long uacc = api.getUACC(results);
				long uac = api.getUserAccountControl(results);
				obj.put("Account Disabled", api.getAccountDisabled(uac));
				obj.put("Password Never Expires", api.getPasswordNeverExpires(uac));
				obj.put("SmartCard Required", api.getSmartCardRequired(uac));
				obj.put("Kerberos PreAuth Required", api.getRequireKrbPreAuth(uac));
				obj.put("Kerberos DES Types Allowed", api.getUseKrbDESTypes(uac));
				obj.put("Use Reversible Encryption Password", api.getUseRevEncryptPasswd(uac));
				obj.put("Allow Delegation", api.getAllowDelegation(uac));
				obj.put("Account LockedOut", api.getLockedOut(uacc));

				List<String> groupList = api.getMemberOf(results);
				JSONArray jsonGroupArray = new JSONArray();

				for (int i = 0; i < groupList.size(); i++) {
					String memberof = api.getSamAccountName(api.getGroupDNAttrs(ldpClient, baseDn, groupList.get(i)));
					jsonGroupArray.put("type=group&attrType=samAccountName&id=" + memberof);
				}
				obj.put("memberOf", jsonGroupArray);
				response.setContentType("application/json");
				response.getWriter().write(obj.toString());
			}
			if (reqtype.equalsIgnoreCase("group")) {
				String groupSamAccountName = null;
				LdapClient ldpClient = new LdapClient(baseDn, bindDn, bindPw, ldapURL);
				LdapApi api = new LdapApi();
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					groupSamAccountName = request.getParameter("id");
				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					groupSamAccountName = api.getSamAccountNameFromCN(ldpClient, baseDn, cn);
				}
				Map<String, Attribute> groupResults = api.getADGroupGCAttrs(ldpClient, baseDn, groupSamAccountName);
				JSONObject obj = new JSONObject();
				obj.put("groupSamAccountName", groupSamAccountName);
				obj.put("cn", api.getCN(groupResults));
				obj.put("dn", api.getDN(groupResults));
				obj.put("email", api.getUserMail(groupResults));
				obj.put("description", api.getDescription(groupResults));
				obj.put("whenChanged", api.getWhenChanged(groupResults));
				obj.put("whenCreated", api.getWhenCreated(groupResults));
				obj.put("uSNCreated", api.getUSNCreated(groupResults));
				obj.put("uSNChanged", api.getUSNChanged(groupResults));
				obj.put("objectGUID", api.getObjectGuid(groupResults));
				obj.put("createTimeStamp", api.getCreateTimeStamp(groupResults));
				obj.put("modifyTimeStamp", api.getModifyTimeStamp(groupResults));
				List<String> groupMbrList = api.getGroupMembers(groupResults);
				JSONArray jsonGroupArray = new JSONArray();
				for (int i = 0; i < groupMbrList.size(); i++) {
					String member = api.getSamAccountName(api.getUserDNAttrs(ldpClient, baseDn, groupMbrList.get(i)));
					jsonGroupArray.put("type=user&attrType=samAccountName&id=" + member);
				}
				obj.put("member", jsonGroupArray);
				response.setContentType("application/json");
				response.getWriter().write(obj.toString());

			}
		} else {
	    response.setContentType("text/html; charset=UTF-8");
	    response.setCharacterEncoding("UTF-8");
	    PrintWriter writer = response.getWriter();

	    request.getRequestDispatcher("header.jsp").include(request, response);
		String reqtype = request.getParameter("type");
			String attrtype = request.getParameter("attrType");
		if (reqtype.equalsIgnoreCase("user")) {
				String samAccountName = null;
			LdapClient ldpClient = new LdapClient(baseDn, bindDn, bindPw, ldapURL);
			LdapApi api = new LdapApi();
				System.out.println("attrype: " + attrtype);
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					samAccountName = request.getParameter("id");
				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					samAccountName = api.getSamAccountNameFromCN(ldpClient, baseDn, cn);
				}
			Map<String,Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
			writer.println("DisplayName: "+api.getDisplayName(results)+"<br>");
			writer.println("CN: "+api.getCN(results)+"<br>");
			writer.println("DN: "+api.getDN(results)+"<br>");
			String manager = api.getSamAccountName(api.getUserDNAttrs(ldpClient, baseDn, api.getManager(results)));
				if (manager != null) {
					writer.println("Manger: <a href=\"Adhelp?type=user&attrType=samAccountName&id=" + manager + "\">"
							+ manager + "</a><br>");
				}
			writer.println("UPN: "+api.getUPN(results)+"<br>");	
			writer.println("Phone: "+api.getPhoneNumber(results)+"<br>");	
			writer.println("Email: "+api.getUserMail(results)+"<br>");
				writer.println("Description: " + api.getDescription(results) + "<br>");
				writer.println("Location: " + api.getLocation(results) + "<br>");
				writer.println("State: " + api.getSt(results) + "<br>");
				writer.println("Country: " + api.getCountry(results) + "<br>");
			writer.println("whenChanged: "+api.getWhenChanged(results)+"<br>");	
			writer.println("whenCreated: "+api.getWhenCreated(results)+"<br>");
			writer.println("uSNCreated: "+api.getUSNCreated(results)+"<br>");	
			writer.println("uSNChanged: "+api.getUSNChanged(results)+"<br>");
				writer.println("objectGUID: " + api.getObjectGuid(results) + "<br>");
			writer.println("createTimeStamp: "+api.getCreateTimeStamp(results)+"<br>");			
			writer.println("modifyTimeStamp: "+api.getModifyTimeStamp(results)+"<br>");
			writer.println("lastLogonTimeStamp: "+api.getLastLogonTimeStamp(results)+"<br>");
			writer.println("pwdLastSet: "+api.getPwdLastSet(results)+"<br>");
			writer.println("lockoutTime: "+api.getLockOutTime(results)+"<br>");
			writer.println("badPwdCount: "+api.getBadPwdCount(results)+"<br>");
			writer.println("badPasswordTime: "+api.getBadPwdTime(results)+"<br>");
			long uacc = api.getUACC(results);
			long uac = api.getUserAccountControl(results);
			writer.println("Account Disabled: "+api.getAccountDisabled(uac)+"<br>");
			writer.println("Password Never Expires: "+api.getPasswordNeverExpires(uac)+"<br>");
			writer.println("SmartCard Required: "+api.getSmartCardRequired(uac)+"<br>");
			writer.println("Kerberos PreAuth Required: "+api.getRequireKrbPreAuth(uac)+"<br>");
			writer.println("Kerberos DES Types Allowed: "+api.getUseKrbDESTypes(uac)+"<br>");
			writer.println("Use Reversible Encryption Password: "+api.getUseRevEncryptPasswd(uac)+"<br>");
			writer.println("Allow Delegation: "+api.getAllowDelegation(uac)+"<br>");
			writer.println("Account LockedOut: "+api.getLockedOut(uacc)+"<br>");

			List<String> groupList = api.getMemberOf(results);
			for (int i = 0; i < groupList.size(); i++) {
				//writer.println("MemberOf: "+groupList.get(i)+"<br>");
				String memberof = api.getSamAccountName(api.getGroupDNAttrs(ldpClient, baseDn, groupList.get(i)));
					writer.println("MemberOf: <a href=\"Adhelp?type=group&attrType=samAccountName&id=" + memberof
							+ "\">" + memberof + "</a><br>");

			}
			writer.flush();
		} 
		if (reqtype.equalsIgnoreCase("group")) {
				String groupSamAccountName = null;
			LdapClient ldpClient = new LdapClient(baseDn, bindDn, bindPw, ldapURL);
			LdapApi api = new LdapApi();
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					groupSamAccountName = request.getParameter("id");
				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					groupSamAccountName = api.getSamAccountNameFromCN(ldpClient, baseDn, cn);
				}
			Map<String,Attribute> groupResults = api.getADGroupGCAttrs(ldpClient, baseDn, groupSamAccountName);

			writer.println("Group: "+groupSamAccountName+"<br>");
			writer.println("CN: "+api.getCN(groupResults)+"<br>");
			writer.println("DN: "+api.getDN(groupResults)+"<br>");
			writer.println("Email: "+api.getUserMail(groupResults)+"<br>");
				writer.println("Description: " + api.getDescription(groupResults) + "<br>");
			writer.println("whenChanged: "+api.getWhenChanged(groupResults)+"<br>");
			writer.println("whenCreated: "+api.getWhenCreated(groupResults)+"<br>");
			writer.println("uSNCreated: "+api.getUSNCreated(groupResults)+"<br>");
			writer.println("uSNChanged: "+api.getUSNChanged(groupResults)+"<br>");
				writer.println("objectGUID: " + api.getObjectGuid(groupResults) + "<br>");
			writer.println("createTimeStamp: "+api.getCreateTimeStamp(groupResults)+"<br>");
			writer.println("modifyTimeStamp: "+api.getModifyTimeStamp(groupResults)+"<br>");
			List<String> groupMbrList = api.getGroupMembers(groupResults);
			for (int i = 0; i < groupMbrList.size(); i++) {
				String member = api.getSamAccountName(api.getUserDNAttrs(ldpClient, baseDn, groupMbrList.get(i)));
					writer.println("Member: <a href=\"Adhelp?type=user&attrType=samAccountName&id=" + member + "\">"
							+ member + "</a><br>");

			}	
			writer.flush();
		}
	    request.getRequestDispatcher("footer.jsp").include(request, response);
		}
		
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse
	 *      response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		// TODO Auto-generated method stub
		doGet(request, response);
	}

}
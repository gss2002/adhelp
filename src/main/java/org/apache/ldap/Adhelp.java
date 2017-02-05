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

import org.apache.adldap.DnsLookup;
import org.apache.adldap.LdapApi;
import org.apache.adldap.LdapClient;
import org.apache.adldap.LdapClientSASL;
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Servlet implementation class Adhelp
 */
public class Adhelp extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static String gcldapURL = "";
	private static String gcbaseDn = "";
	private static final Logger LOG = LoggerFactory.getLogger(Adhelp.class);



	/**
	 * Default constructor.
	 */
	public Adhelp() {
		// TODO Auto-generated constructor stub
		gcbaseDn = "dc=hdpusr,dc=senia,dc=org";
		gcldapURL = "ldap://seniadc1.senia.org:3268";

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
				LdapClient gcldpClient = new LdapClientSASL(gcbaseDn, gcldapURL, KerberosCreds.getSubject());
				LdapApi gcapi = new LdapApi();
				LOG.info("attrType: " + attrtype);
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					samAccountName = request.getParameter("id");
					LOG.info("usersamAccountName: " + samAccountName);

				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					LOG.info("usercn: " + cn);
					samAccountName = gcapi.getSamAccountNameFromCN(gcldpClient, gcbaseDn, cn);
				}
				String dn = gcapi.getDN(gcldpClient, gcbaseDn, samAccountName);
				String domain_interim = dn.split(",DC=", 2)[1];
				String domain_baseDN = "DC="+domain_interim;
				LOG.debug("dn: "+dn);
				LOG.debug("baseDN="+domain_baseDN);
				String domain = domain_baseDN.replace("DC=", "").replace(",", ".");
		        String baseDn = domain_baseDN;
		        LOG.debug(domain_baseDN);
		        LOG.debug(domain);

		        DnsLookup dns = new DnsLookup();
		        String ldapServer = dns.getLdapServer(domain);
		        String ldapUrl = "ldap://"+ldapServer+":389";
				LdapClient ldpClient = new LdapClientSASL(baseDn,ldapUrl, KerberosCreds.getSubject());
				LdapApi api = new LdapApi();
				Map<String, Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
				JSONObject obj = new JSONObject();
				obj.put("displayName", api.getDisplayName(results));
				obj.put("samAccountName", api.getSamAccountName(results));
				obj.put("cn", api.getCN(results));
				obj.put("dn", api.getDN(results));
				String manager = api.getSamAccountName(api.getUserDNAttrs(ldpClient, baseDn, api.getManager(results)));
				if (manager != null) {
					LOG.debug("manager: " + manager);
					obj.put("manager", "type=user&attrType=samAccountName&id=" + manager);
				}
				obj.put("eUPN", api.getUPN(results));
				obj.put("iUPN", api.getSamAccountName(results)+"@"+domain);
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
				obj.put("objectGUID", api.getObjectGuid(results).replace("<GUID=", "").replace(">", ""));
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
				if (groupList != null ) {
					JSONArray jsonGroupArray = new JSONArray();
					for (int i = 0; i < groupList.size(); i++) {
						String memberof = gcapi.getSamAccountName(gcapi.getGroupDNAttrs(gcldpClient, gcbaseDn, groupList.get(i)));
						LOG.debug("member: " + memberof);
						jsonGroupArray.put("type=group&attrType=samAccountName&id=" + memberof);
					}
					obj.put("memberOf", jsonGroupArray);
				}
				LdapClient.destroyLdapClient(gcldpClient.getLdapBean().getLdapCtx());
				LdapClient.destroyLdapClient(ldpClient.getLdapBean().getLdapCtx());
				response.setContentType("application/json");
				response.getWriter().write(obj.toString());


			}
			if (reqtype.equalsIgnoreCase("group")) {
				String groupSamAccountName = null;
				LdapClient gcldpClient = new LdapClientSASL(gcbaseDn, gcldapURL, KerberosCreds.getSubject());
				LdapApi gcapi = new LdapApi();
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					groupSamAccountName = request.getParameter("id");
					LOG.info("groupSamAccountName: " + groupSamAccountName);
				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					LOG.info("groupCn: " + cn);
					groupSamAccountName = gcapi.getSamAccountNameFromCN(gcldpClient, gcbaseDn, cn);
				}
				Map<String, Attribute> groupResults = gcapi.getADGroupGCAttrs(gcldpClient, gcbaseDn, groupSamAccountName);
				JSONObject obj = new JSONObject();
				obj.put("groupSamAccountName", groupSamAccountName);
				obj.put("cn", gcapi.getCN(groupResults));
				obj.put("dn", gcapi.getDN(groupResults));
				obj.put("email", gcapi.getUserMail(groupResults));
				obj.put("description", gcapi.getDescription(groupResults));
				obj.put("whenChanged", gcapi.getWhenChanged(groupResults));
				obj.put("whenCreated", gcapi.getWhenCreated(groupResults));
				obj.put("uSNCreated", gcapi.getUSNCreated(groupResults));
				obj.put("uSNChanged", gcapi.getUSNChanged(groupResults));
				obj.put("objectGUID", gcapi.getObjectGuid(groupResults));
				obj.put("createTimeStamp", gcapi.getCreateTimeStamp(groupResults));
				obj.put("modifyTimeStamp", gcapi.getModifyTimeStamp(groupResults));
				if(gcapi.groupRangingExists(groupResults)) {
					LOG.info("getGroupMembers - Ranging=TRUE");
					JSONArray jsonGroupArray = new JSONArray();

					List<String> groupMbrList = gcapi.getGroupMemberRanging(gcldpClient, gcbaseDn,groupSamAccountName);
					for (int i = 0; i < groupMbrList.size(); i++) {
						LOG.debug("member: " + groupMbrList.get(i));
						String member = gcapi.getSamAccountName(gcapi.getUserDNAttrs(gcldpClient, gcbaseDn, groupMbrList.get(i)));
						LOG.debug("member: " + member);
						jsonGroupArray.put("type=user&attrType=samAccountName&id=" + member);
					}
					obj.put("member", jsonGroupArray);
					obj.put("groupCount", groupMbrList.size());
				} else {
					LOG.info("getGroupMembers - Ranging=FALSE");
					List<String> groupMbrList = gcapi.getGroupMembers(groupResults);
					if (groupMbrList != null) {
						JSONArray jsonGroupArray = new JSONArray();
						for (int i = 0; i < groupMbrList.size(); i++) {
							String member = gcapi.getSamAccountName(gcapi.getUserDNAttrs(gcldpClient, gcbaseDn, groupMbrList.get(i)));
							LOG.debug("member: " + member);
							jsonGroupArray.put("type=user&attrType=samAccountName&id=" + member);
						}
						obj.put("member", jsonGroupArray);
						obj.put("groupCount", groupMbrList.size());
					}

				}
	
				LdapClient.destroyLdapClient(gcldpClient.getLdapBean().getLdapCtx());
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
				LdapClient gcldpClient = new LdapClientSASL(gcbaseDn, gcldapURL, KerberosCreds.getSubject());
				LdapApi gcapi = new LdapApi();
				LOG.debug("attrype: " + attrtype);
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					samAccountName = request.getParameter("id");
					LOG.info("UsersamAccountName: " + samAccountName);

				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					LOG.info("usercn: " + cn);
					samAccountName = gcapi.getSamAccountNameFromCN(gcldpClient, gcbaseDn, cn);
				}
				String dn = gcapi.getDN(gcldpClient, gcbaseDn, samAccountName);
				String domain_interim = dn.split(",DC=", 2)[1];
				String domain_baseDN = "DC="+domain_interim;
				LOG.debug("dn: "+dn);
				LOG.debug("baseDN="+domain_baseDN);
				String domain = domain_baseDN.replace("DC=", "").replace(",", ".");
		        String baseDn = domain_baseDN;
		        LOG.debug(domain_baseDN);
		        LOG.debug(domain);

		        DnsLookup dns = new DnsLookup();
		        String ldapServer = dns.getLdapServer(domain);
		        String ldapUrl = "ldap://"+ldapServer+":389";
				LdapClient ldpClient = new LdapClientSASL(baseDn,ldapUrl, KerberosCreds.getSubject());
				LdapApi api = new LdapApi();
				Map<String, Attribute> results = api.getADUserGCAttrs(ldpClient, baseDn, samAccountName);
				writer.println("DisplayName: " + gcapi.getDisplayName(results) + "<br>");
				writer.println("samAccountName: " + gcapi.getSamAccountName(results) + "<br>");
				writer.println("CN: " + api.getCN(results) + "<br>");
				writer.println("DN: " + api.getDN(results) + "<br>");
				String manager = api.getSamAccountName(api.getUserDNAttrs(ldpClient, baseDn, api.getManager(results)));
				if (manager != null) {
					LOG.debug("managerSamAccountName: " + manager);
					writer.println("Manger: <a href=\"Adhelp?type=user&attrType=samAccountName&id=" + manager + "\">"
							+ manager + "</a><br>");
				}
				writer.println("eUPN: " + api.getUPN(results) + "<br>");
				writer.println("iUPN: " +api.getSamAccountName(results)+"@"+domain + "<br>");
				writer.println("Phone: " + api.getPhoneNumber(results) + "<br>");
				writer.println("Email: " + api.getUserMail(results) + "<br>");
				writer.println("Description: " + api.getDescription(results) + "<br>");
				writer.println("Location: " + api.getLocation(results) + "<br>");
				writer.println("State: " + api.getSt(results) + "<br>");
				writer.println("Country: " + api.getCountry(results) + "<br>");
				writer.println("whenChanged: " + api.getWhenChanged(results) + "<br>");
				writer.println("whenCreated: " + api.getWhenCreated(results) + "<br>");
				writer.println("uSNCreated: " + api.getUSNCreated(results) + "<br>");
				writer.println("uSNChanged: " + api.getUSNChanged(results) + "<br>");
				writer.println("objectGUID: " + api.getObjectGuid(results).replace("<GUID=", "").replace(">", "") + "<br>");
				writer.println("createTimeStamp: " + api.getCreateTimeStamp(results) + "<br>");
				writer.println("modifyTimeStamp: " + api.getModifyTimeStamp(results) + "<br>");
				writer.println("lastLogonTimeStamp: " + api.getLastLogonTimeStamp(results) + "<br>");
				writer.println("pwdLastSet: " + api.getPwdLastSet(results) + "<br>");
				writer.println("lockoutTime: " + api.getLockOutTime(results) + "<br>");
				writer.println("badPwdCount: " + api.getBadPwdCount(results) + "<br>");
				writer.println("badPasswordTime: " + api.getBadPwdTime(results) + "<br>");

				long uacc = api.getUACC(results);
				long uac = api.getUserAccountControl(results);
				writer.println("Account Disabled: " + api.getAccountDisabled(uac) + "<br>");
				writer.println("Password Never Expires: " + api.getPasswordNeverExpires(uac) + "<br>");
				writer.println("SmartCard Required: " + api.getSmartCardRequired(uac) + "<br>");
				writer.println("Kerberos PreAuth Required: " + api.getRequireKrbPreAuth(uac) + "<br>");
				writer.println("Kerberos DES Types Allowed: " + api.getUseKrbDESTypes(uac) + "<br>");
				writer.println("Use Reversible Encryption Password: " + api.getUseRevEncryptPasswd(uac) + "<br>");
				writer.println("Allow Delegation: " + api.getAllowDelegation(uac) + "<br>");
				writer.println("Account LockedOut: " + api.getLockedOut(uacc) + "<br>");
				List<String> groupList = api.getMemberOf(results);
				if (groupList != null ) {
					for (int i = 0; i < groupList.size(); i++) {
						// writer.println("MemberOf: "+groupList.get(i)+"<br>");
						LOG.debug("memberOf: " + groupList.get(i));
						String memberof = gcapi.getSamAccountName(gcapi.getGroupDNAttrs(gcldpClient, gcbaseDn, groupList.get(i)));
						LOG.debug("memberOfSamAccountName: " + memberof);
						writer.println("MemberOf: <a href=\"Adhelp?type=group&attrType=samAccountName&id=" + memberof
								+ "\">" + memberof + "</a><br>");

					}
				}
				LdapClient.destroyLdapClient(ldpClient.getLdapBean().getLdapCtx());
				LdapClient.destroyLdapClient(gcldpClient.getLdapBean().getLdapCtx());
				writer.flush();
			}
			if (reqtype.equalsIgnoreCase("group")) {
				String groupSamAccountName = null;
				LdapClient gcldpClient = new LdapClientSASL(gcbaseDn, gcldapURL, KerberosCreds.getSubject());
				LdapApi gcapi = new LdapApi();
				if (attrtype.equalsIgnoreCase("samAccountName")) {
					groupSamAccountName = request.getParameter("id");
					LOG.info("groupSamAccountName: " + groupSamAccountName);
				}
				if (attrtype.equalsIgnoreCase("cn")) {
					String cn = request.getParameter("id");
					LOG.info("cn: " + cn);
					groupSamAccountName = gcapi.getSamAccountNameFromCN(gcldpClient, gcbaseDn, cn);
				}
				Map<String, Attribute> groupResults = gcapi.getADGroupGCAttrs(gcldpClient, gcbaseDn, groupSamAccountName);
				writer.println("Group: " + groupSamAccountName + "<br>");
				writer.println("CN: " + gcapi.getCN(groupResults) + "<br>");
				writer.println("DN: " + gcapi.getDN(groupResults) + "<br>");
				writer.println("Email: " + gcapi.getUserMail(groupResults) + "<br>");
				writer.println("Description: " + gcapi.getDescription(groupResults) + "<br>");
				writer.println("whenChanged: " + gcapi.getWhenChanged(groupResults) + "<br>");
				writer.println("whenCreated: " + gcapi.getWhenCreated(groupResults) + "<br>");
				writer.println("uSNCreated: " + gcapi.getUSNCreated(groupResults) + "<br>");
				writer.println("uSNChanged: " + gcapi.getUSNChanged(groupResults) + "<br>");
				writer.println("objectGUID: " + gcapi.getObjectGuid(groupResults) + "<br>");
				writer.println("createTimeStamp: " + gcapi.getCreateTimeStamp(groupResults) + "<br>");
				writer.println("modifyTimeStamp: " + gcapi.getModifyTimeStamp(groupResults) + "<br>");
				if(gcapi.groupRangingExists(groupResults)) {
					LOG.info("getGroupMembers - Ranging=TRUE");
					List<String> groupMbrList = gcapi.getGroupMemberRanging(gcldpClient, gcbaseDn,groupSamAccountName);
					for (int i = 0; i < groupMbrList.size(); i++) {
						LOG.debug("member: " + groupMbrList.get(i));
						String member = gcapi.getSamAccountName(gcapi.getUserDNAttrs(gcldpClient, gcbaseDn, groupMbrList.get(i)));
						LOG.debug("memberSamAccountName: " + member);
						writer.println("Member: <a href=\"Adhelp?type=user&attrType=samAccountName&id=" + member + "\">"
								+ member + "</a><br>");
					}
					writer.println("groupCount: " + groupMbrList.size() + "<br>");
					
				} else {
					LOG.info("getGroupMembers - Ranging=FALSE");
					List<String> groupMbrList = gcapi.getGroupMembers(groupResults);
					if (groupMbrList != null) {
						for (int i = 0; i < groupMbrList.size(); i++) {
							LOG.debug("member: " + groupMbrList.get(i));
							String member = gcapi.getSamAccountName(gcapi.getUserDNAttrs(gcldpClient, gcbaseDn, groupMbrList.get(i)));
							LOG.debug("memberSamAccountName: " + member);
							writer.println("Member: <a href=\"Adhelp?type=user&attrType=samAccountName&id=" + member + "\">"
									+ member + "</a><br>");

						}	
						writer.println("groupCount: " + groupMbrList.size() + "<br>");
					}

				}

				LdapClient.destroyLdapClient(gcldpClient.getLdapBean().getLdapCtx());
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

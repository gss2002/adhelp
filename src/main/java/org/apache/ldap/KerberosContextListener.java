package org.apache.ldap;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.adldap.KerberosClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Application Lifecycle Listener implementation class KerberosContextListener
 *
 */
public class KerberosContextListener implements ServletContextListener, Runnable {
	private Thread t;
	private KerberosClient krbClient;
	private final Object lock = new Object();
	private String keytab;
	private String principalName;
	private static final Logger LOG = LoggerFactory.getLogger(KerberosContextListener.class);


	/**
	 * Default constructor.
	 */
	public KerberosContextListener() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see ServletContextListener#contextDestroyed(ServletContextEvent)
	 */
	public void contextDestroyed(ServletContextEvent sce) {
		t.interrupt();
	}

	/**
	 * @see ServletContextListener#contextInitialized(ServletContextEvent)
	 */
	public void contextInitialized(ServletContextEvent sce) {
		keytab = System.getProperty("adhelp.keytab");
		principalName = System.getProperty("adhelp.principalName");
		LOG.info("KeyTab: "+keytab);
		LOG.info("principalName: "+principalName);

		krbClient = new KerberosClient(principalName, null, keytab);
		t = new Thread(this);
		t.start();
		LOG.info("Kerberos Renewal thread started");
	}

	public void run() {
		synchronized (lock) {

			try {
				while (true) {
					KerberosCreds.setSubject(krbClient.getSubject());
					LOG.debug("daemon working...");
					lock.wait(18000000L);
					krbClient.reinitContext();

				}
			} catch (InterruptedException e) {
				LOG.info("kerberos renewal thread stopped");
			}
		}
	}

}

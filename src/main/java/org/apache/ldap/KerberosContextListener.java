package org.apache.ldap;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.apache.adldap.KerberosClient;


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
		System.out.println("KeyTab: "+keytab);
		System.out.println("principalName: "+principalName);

		krbClient = new KerberosClient(principalName, null, keytab);
		t = new Thread(this);
		t.start();
		System.out.println("Kerberos Renewal thread started");
	}

	public void run() {
		synchronized (lock) {

			try {
				while (true) {
					KerberosCreds.setSubject(krbClient.getSubject());
					System.out.println("deamon working...");
					lock.wait(18000000L);
					krbClient.reinitContext();

				}
			} catch (InterruptedException e) {
				System.out.println("kerberos renewal thread stopped");
			}
		}
	}

}

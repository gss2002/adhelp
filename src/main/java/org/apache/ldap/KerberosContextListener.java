/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.ldap;

import org.apache.adldap.KerberosClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;


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

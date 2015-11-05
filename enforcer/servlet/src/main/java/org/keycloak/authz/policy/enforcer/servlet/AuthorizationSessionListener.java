package org.keycloak.authz.policy.enforcer.servlet;

import javax.servlet.annotation.WebListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@WebListener
public class AuthorizationSessionListener implements HttpSessionListener {
    @Override
    public void sessionCreated(HttpSessionEvent se) {
        se.toString();
    }

    @Override
    public void sessionDestroyed(HttpSessionEvent se) {

    }
}

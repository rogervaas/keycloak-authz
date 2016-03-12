package org.keycloak.authz.server.services.core;

import org.keycloak.authz.core.policy.ExecutionContext;
import org.keycloak.authz.server.services.core.util.Tokens;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultExecutionContext implements ExecutionContext {

    private final RealmModel realm;
    private final KeycloakSession keycloakSession;

    public DefaultExecutionContext(KeycloakSession keycloakSession, RealmModel realm) {
        this.keycloakSession = keycloakSession;
        this.realm = realm;
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        HashMap<String, List<String>> attributes = new HashMap<>();

        attributes.put("kc.authz.context.time.date_time", Arrays.asList(new SimpleDateFormat("MM/dd/yyyy hh:mm:ss").format(new Date())));
        attributes.put("kc.authz.context.client.network.ip_address", Arrays.asList(keycloakSession.getContext().getConnection().getRemoteAddr()));
        attributes.put("kc.authz.context.client.network.host", Arrays.asList(keycloakSession.getContext().getConnection().getRemoteHost()));

        AccessToken accessToken = Tokens.getAccessToken(keycloakSession, realm);

        attributes.put("kc.authz.context.client_id", Arrays.asList(accessToken.getIssuedFor()));

        List<String> userAgents = keycloakSession.getContext().getRequestHeaders().getRequestHeader("User-Agent");

        if (userAgents != null) {
            attributes.put("kc.authz.context.client.user_agent", userAgents);
        }

        attributes.put("kc.authz.context.authc.realm", Arrays.asList(realm.getName()));

        return attributes;
    }
}

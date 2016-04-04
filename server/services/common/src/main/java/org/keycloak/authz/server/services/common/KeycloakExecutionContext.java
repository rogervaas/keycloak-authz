package org.keycloak.authz.server.services.common;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakExecutionContext implements EvaluationContext {

    private final RealmModel realm;
    private final KeycloakIdentity identity;

    public KeycloakExecutionContext(RealmModel realm) {
        this(new KeycloakIdentity(realm), realm);
    }

    public KeycloakExecutionContext(KeycloakIdentity identity, RealmModel realm) {
        this.identity = identity;
        this.realm = realm;
    }

    @Override
    public Identity getIdentity() {
        return this.identity;
    }

    @Override
    public RealmModel getRealm() {
        return this.realm;
    }

    @Override
    public Attributes getAttributes() {
        HashMap<String, Collection<String>> attributes = new HashMap<>();
        KeycloakSession keycloakSession = getKeycloakSession();

        attributes.put("kc.authz.context.time.date_time", Arrays.asList(new SimpleDateFormat("MM/dd/yyyy hh:mm:ss").format(new Date())));
        attributes.put("kc.authz.context.client.network.ip_address", Arrays.asList(keycloakSession.getContext().getConnection().getRemoteAddr()));
        attributes.put("kc.authz.context.client.network.host", Arrays.asList(keycloakSession.getContext().getConnection().getRemoteHost()));

        AccessToken accessToken = this.identity.getAccessToken();

        if (accessToken != null) {
            attributes.put("kc.authz.context.client_id", Arrays.asList(accessToken.getIssuedFor()));
        }

        List<String> userAgents = keycloakSession.getContext().getRequestHeaders().getRequestHeader("User-Agent");

        if (userAgents != null) {
            attributes.put("kc.authz.context.client.user_agent", userAgents);
        }

        attributes.put("kc.authz.context.authc.realm", Arrays.asList(realm.getName()));

        return Attributes.from(attributes);
    }

    public KeycloakSession getKeycloakSession() {
        return ResteasyProviderFactory.getContextData(KeycloakSession.class);
    }
}

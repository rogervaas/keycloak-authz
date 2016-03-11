package org.keycloak.authz.server.services.core.util;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class Tokens {

    public static AccessToken getAccessToken(KeycloakSession keycloakSession, RealmModel realm) {
        AppAuthManager authManager = new AppAuthManager();
        AuthenticationManager.AuthResult authResult = authManager.authenticateBearerToken(keycloakSession, realm, keycloakSession.getContext().getUri(), keycloakSession.getContext().getConnection(), keycloakSession.getContext().getRequestHeaders());

        if (authResult != null) {
            return authResult.getToken();
        }

        return null;
    }

    public static String getAccessTokenAsString(KeycloakSession keycloakSession) {
        AppAuthManager authManager = new AppAuthManager();

        return authManager.extractAuthorizationHeaderToken(keycloakSession.getContext().getRequestHeaders());
    }
}

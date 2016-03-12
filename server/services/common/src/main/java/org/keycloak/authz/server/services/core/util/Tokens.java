package org.keycloak.authz.server.services.core.util;

import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

import javax.ws.rs.core.Response;
import java.security.PublicKey;

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

    public static boolean verifySignature(String token, PublicKey publicKey) {
        try {
            JWSInput jws = new JWSInput(token);

            return RSAProvider.verify(jws, publicKey);
        } catch (Exception e) {
            throw new ErrorResponseException("invalid_signature", "Unexpected error while validating signature.", Response.Status.INTERNAL_SERVER_ERROR);
        }
    }
}

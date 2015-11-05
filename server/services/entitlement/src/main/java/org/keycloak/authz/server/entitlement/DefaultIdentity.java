/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authz.server.entitlement;

import java.util.Set;
import org.keycloak.authz.core.Identity;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DefaultIdentity implements Identity {

    private final AccessToken accessToken;
    private final KeycloakSession keycloakSession;

    public static Identity create(RealmModel realm, KeycloakSession keycloakSession) {
        AccessToken token = getAccessToken(keycloakSession, realm);

        if (token == null) {
            throw new RuntimeException("Invalid or non-existent access token.");
        }

        return new DefaultIdentity(token, keycloakSession);
    }

    private static AccessToken getAccessToken(KeycloakSession keycloakSession, RealmModel realm) {
        AppAuthManager authManager = new AppAuthManager();
        AuthenticationManager.AuthResult authResult = authManager.authenticateBearerToken(keycloakSession, realm, keycloakSession.getContext().getUri(), keycloakSession.getContext().getConnection(), keycloakSession.getContext().getRequestHeaders());

        if (authResult != null) {
            return authResult.getToken();
        }

        return null;
    }

    DefaultIdentity(AccessToken accessToken, KeycloakSession keycloakSession) {
        this.accessToken = accessToken;
        this.keycloakSession = keycloakSession;
    }

    @Override
    public String getId() {
        if (isResourceServer()) {
            ClientSessionModel clientSession = this.keycloakSession.sessions().getClientSession(this.accessToken.getClientSession());
            return clientSession.getClient().getId();
        }

        return this.accessToken.getSubject();
    }

    @Override
    public String getResourceServerId() {
        ClientSessionModel clientSession = this.keycloakSession.sessions().getClientSession(this.accessToken.getClientSession());
        return clientSession.getClient().getId();
    }

    @Override
    public boolean hasRole(String scope) {
        AccessToken.Access realmAccess = this.accessToken.getRealmAccess();

        if (realmAccess != null) {
            Set<String> roles = realmAccess.getRoles();

            if (roles != null && roles.contains(scope)) {
                return true;
            }
        }

        ClientSessionModel clientSession = this.keycloakSession.sessions().getClientSession(this.accessToken.getClientSession());

        for (String roleId : clientSession.getRoles()) {
            RoleModel id = this.keycloakSession.realms().getRoleById(roleId, clientSession.getRealm());

            if (scope.equals(id.getName())) {
                return true;
            }
        }

        return false;
    }

    @Override
    public boolean isResourceServer() {
        ClientSessionModel clientSession = this.keycloakSession.sessions().getClientSession(this.accessToken.getClientSession());
        UserModel clientUser = this.keycloakSession.users().getUserByServiceAccountClient(clientSession.getClient());

        if (clientUser == null) {
            return false;
        }

        return this.accessToken.getSubject().equals(clientUser.getId());
    }
}

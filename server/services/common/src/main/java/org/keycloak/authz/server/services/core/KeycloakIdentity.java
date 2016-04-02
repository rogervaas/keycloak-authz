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
package org.keycloak.authz.server.services.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.models.ClientSessionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.ErrorResponseException;
import org.keycloak.services.managers.AppAuthManager;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import static org.keycloak.authz.server.services.core.util.Tokens.getAccessToken;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class KeycloakIdentity implements Identity {

    private final AccessToken accessToken;
    private final KeycloakSession keycloakSession;

    public static KeycloakIdentity create(RealmModel realm, KeycloakSession keycloakSession) {
        AccessToken token = getAccessToken(keycloakSession, realm);

        if (token == null) {
            throw new ErrorResponseException("invalid_bearer_token", "Could not obtain bearer access_token from request.", Response.Status.FORBIDDEN);
        }

        return new KeycloakIdentity(token, keycloakSession);
    }

    private KeycloakIdentity(AccessToken accessToken, KeycloakSession keycloakSession) {
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
    public Attributes getAttributes() {
        HashMap<String, Collection<String>> attributes = new HashMap<>();
        AppAuthManager authManager = new AppAuthManager();
        String token = authManager.extractAuthorizationHeaderToken(this.keycloakSession.getContext().getRequestHeaders());

        try {
            String claims = new JWSInput(token).readContentAsString();
            ObjectNode objectNode = (ObjectNode) new ObjectMapper().readTree(claims);
            Iterator<String> iterator = objectNode.fieldNames();
            List<String> roleNames = new ArrayList<>();

            while (iterator.hasNext()) {
                String fieldName = iterator.next();
                JsonNode fieldValue = objectNode.get(fieldName);
                List<String> values = new ArrayList<>();

                values.add(fieldValue.toString());

                if (fieldName.equals("realm_access")) {
                    JsonNode grantedRoles = fieldValue.get("roles");

                    if (grantedRoles != null) {
                        Iterator<JsonNode> rolesIt = grantedRoles.iterator();

                        while (rolesIt.hasNext()) {
                            roleNames.add(rolesIt.next().asText());
                        }
                    }
                }

                if (fieldName.equals("resource_access")) {
                    Iterator<JsonNode> resourceAccessIt = fieldValue.iterator();

                    while (resourceAccessIt.hasNext()) {
                        JsonNode grantedRoles = resourceAccessIt.next().get("roles");

                        if (grantedRoles != null) {
                            Iterator<JsonNode> rolesIt = grantedRoles.iterator();

                            while (rolesIt.hasNext()) {
                                roleNames.add(rolesIt.next().asText());
                            }
                        }
                    }
                }

                attributes.put(fieldName, values);
            }

            attributes.put("roles", roleNames);
        } catch (Exception e) {
            throw new RuntimeException("Error while reading attributes from security token.", e);
        }

        return Attributes.from(attributes);
    }

    /**
     * Indicates if this identity is granted with a role with the given <code>roleName</code>.
     *
     * @param roleName the name of the role
     *
     * @return true if the identity has the given role. Otherwise, it returns false.
     */
    public boolean hasRole(String roleName) {
        return getAttributes().containsValue("roles", roleName);
    }


    public boolean isResourceServer() {
        ClientSessionModel clientSession = this.keycloakSession.sessions().getClientSession(this.accessToken.getClientSession());
        UserModel clientUser = this.keycloakSession.users().getUserByServiceAccountClient(clientSession.getClient());

        if (clientUser == null) {
            return false;
        }

        return this.accessToken.getSubject().equals(clientUser.getId());
    }
}

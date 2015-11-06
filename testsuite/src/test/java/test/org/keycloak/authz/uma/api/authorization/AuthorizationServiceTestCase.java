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
package test.org.keycloak.authz.uma.api.authorization;

import org.junit.Test;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.AuthorizationRequest;
import org.keycloak.authz.client.representation.AuthorizationResponse;
import org.keycloak.authz.client.representation.PermissionRequest;
import org.keycloak.authz.client.representation.PermissionResponse;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.authz.client.resource.AuthorizationResource;
import org.keycloak.authz.client.resource.ProtectedResource;
import org.keycloak.authz.server.uma.ErrorResponse;
import org.keycloak.authz.server.uma.authorization.Permission;
import org.keycloak.authz.server.uma.authorization.RequestingPartyToken;
import org.keycloak.jose.jws.JWSInput;

import javax.ws.rs.BadRequestException;
import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationServiceTestCase {

    private final AuthzClient authzClient = AuthzClient.fromConfig(URI.create("http://localhost:8080/auth/realms/photoz/authz/uma_configuration"));

    @Test
    public void testResourceServerIsOwner() throws Exception {
        ResourceRepresentation resource = createResource();
        String[] expectedScopes = resource.getScopes().stream()
                .map(ScopeRepresentation::getName).collect(Collectors.toSet()).toArray(new String[resource.getScopes().size()]);
        PermissionResponse ticket = obtainPermissionTicket(resource.getId(), expectedScopes);
        AuthorizationResource authorization = this.authzClient
                .authorization("jdoe", "jdoe");

        AuthorizationResponse authorize = authorization.authorize(new AuthorizationRequest(ticket.getTicket()));
        RequestingPartyToken token = new JWSInput(authorize.getRpt()).readJsonContent(RequestingPartyToken.class);
        List<Permission> permissions = token.getPermissions();

        assertEquals(1, permissions.size());
        Permission permission = permissions.iterator().next();

        assertEquals(resource.getId(), permission.getResourceSetId());

        Set<String> scopes = permission.getScopes();

        assertEquals(2, scopes.size());
        assertTrue(scopes.containsAll(Arrays.asList(expectedScopes)));
    }

    @Test
    public void testInvalidTicket() {
        AuthorizationResource authorization = this.authzClient
                .authorization("jdoe", "jdoe");

        try {
            authorization.authorize(new AuthorizationRequest("invalid_ticket"));
            fail("Error expected.");
        } catch (BadRequestException bde) {
            ErrorResponse response = bde.getResponse().readEntity(ErrorResponse.class);

            assertEquals("invalid_ticket", response.getError());
        } catch (Exception e) {
            e.printStackTrace();;
            fail("Unexpected exception.");
        }
    }

    private PermissionResponse obtainPermissionTicket(String resourceId, String... scopes) {
        AuthzClient.ProtectionClient protection = this.authzClient
                .protection("photoz-restful-api", "06cb5239-8ade-4c06-a65b-2aadb4e8ee51");

        return protection.permission().forResource(new PermissionRequest(resourceId, scopes));
    }

    private ResourceRepresentation createResource() {
        ResourceRepresentation description = newResource("Admin Resources", new ScopeRepresentation("http://photoz.example.com/dev/scopes/scope1"), new ScopeRepresentation("http://photoz.example.com/dev/scopes/scope2"));
        ProtectedResource resource = this.authzClient
                .protection("photoz-restful-api", "06cb5239-8ade-4c06-a65b-2aadb4e8ee51")
                .resource();

        return resource.findById(resource.create(description).getId()).getResourceDescription();
    }

    private ResourceRepresentation newResource(String name, ScopeRepresentation... scopes) {
        return new ResourceRepresentation(name, new HashSet<>(Arrays.asList(scopes)));
    }
}
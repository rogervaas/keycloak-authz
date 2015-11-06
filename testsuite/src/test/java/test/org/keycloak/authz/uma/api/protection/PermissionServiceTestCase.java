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
package test.org.keycloak.authz.uma.api.protection;

import org.junit.Test;
import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.PermissionRequest;
import org.keycloak.authz.client.representation.PermissionResponse;
import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.services.ErrorResponse;

import javax.ws.rs.BadRequestException;
import java.net.URI;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionServiceTestCase {

    @Test
    public void testObtainPermissionTicket() {
        String resourceName = "Admin Resources";
        String resourceUri = "http://photoz.example.com/admin/*";
        String resourceType = "http://www.keycloak-authz.org/rtype/uri";
        Set<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("http://photoz.example.com/dev/scopes/admin"));

        ResourceRepresentation resourceDescription = new ResourceRepresentation(resourceName, scopes,
                resourceUri,
                resourceType);
        AuthzClient.ProtectionClient protection = AuthzClient.fromConfig(URI.create("http://localhost:8080/auth/realms/photoz/authz/uma_configuration"))
                .protection();
        RegistrationResponse resource = protection.resource().create(resourceDescription);
        String resourceId = resource.getId();
        PermissionResponse response = protection.permission().forResource(new PermissionRequest(resourceId, "http://photoz.example.com/dev/scopes/admin"));

        assertNotNull(response.getTicket());
    }

    @Test
    public void testInvalidResourceId() {
        AuthzClient.ProtectionClient protection = AuthzClient.fromConfig(URI.create("http://localhost:8080/auth/realms/photoz/authz/uma_configuration"))
                .protection();

        try {
            protection.permission().forResource(new PermissionRequest("invalid_resource_id", "http://photoz.example.com/dev/scopes/admin"));
            fail("Error expected.");
        } catch (BadRequestException bde) {
            assertTrue(bde.getResponse().readEntity(String.class).contains("invalid_resource_set_id"));
        } catch (Exception e) {
            e.printStackTrace();;
            fail("Unexpected exception.");
        }
    }

    @Test
    public void testInvalidScope() {
        String resourceName = "Admin Resources";
        String resourceUri = "http://photoz.example.com/admin/*";
        String resourceType = "http://www.keycloak-authz.org/rtype/uri";
        Set<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("http://photoz.example.com/dev/scopes/admin"));

        ResourceRepresentation resourceDescription = new ResourceRepresentation(resourceName, scopes,
                resourceUri,
                resourceType);
        AuthzClient.ProtectionClient protection = AuthzClient.fromConfig(URI.create("http://localhost:8080/auth/realms/photoz/authz/uma_configuration"))
                .protection();
        String resourceId = protection.resource().create(resourceDescription).getId();

        try {
            protection.permission().forResource(new PermissionRequest(resourceId, "http://photoz.example.com/dev/scopes/admin_invalid"));
            fail("Error expected.");
        } catch (BadRequestException bde) {
            ErrorResponse response = bde.getResponse().readEntity(ErrorResponse.class);

            assertTrue(bde.getResponse().readEntity(String.class).contains("invalid_scope"));
        } catch (Exception e) {
            e.printStackTrace();;
            fail("Unexpected exception.");
        }
    }
}
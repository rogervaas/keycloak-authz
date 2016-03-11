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
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;

import javax.ws.rs.BadRequestException;
import java.util.HashSet;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionServiceTestCase extends AbstractProtectionTestCase {

    @Test
    public void testObtainPermissionTicket() {
        HashSet<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("urn:photoz.com:scopes:album:admin:manage"));

        ResourceRepresentation resourceDescription = createResource("Protected Resource", null, null, null, null, scopes);
        String resourceId = resourceDescription.getId();
        PermissionResponse response = this.authzClient.protection().permission().forResource(new PermissionRequest(resourceId, "urn:photoz.com:scopes:album:admin:manage"));
        assertNotNull(response.getTicket());
    }

    @Test
    public void testInvalidResourceId() {
        AuthzClient.ProtectionClient protection = this.authzClient.protection();

        try {
            protection.permission().forResource(new PermissionRequest("invalid_resource_id", "http://photoz.example.com/dev/scopes/admin"));
            fail("Error expected.");
        } catch (BadRequestException bde) {
            assertTrue(bde.getResponse().readEntity(String.class).contains("nonexistent_resource_set_id"));
        } catch (Exception e) {
            e.printStackTrace();;
            fail("Unexpected exception.");
        }
    }

    @Test
    public void testInvalidScope() {
        HashSet<ScopeRepresentation> scopes = new HashSet<>();

        scopes.add(new ScopeRepresentation("urn:photoz.com:scopes:album:admin:manage"));

        ResourceRepresentation resourceDescription = createResource("Protected Resource", null, null, null, null, scopes);
        String resourceId = resourceDescription.getId();

        try {
            this.authzClient.protection().permission().forResource(new PermissionRequest(resourceId, "urn:photoz.com:scopes:album:admin:invalid_scope"));
            fail("Error expected.");
        } catch (BadRequestException bde) {
            assertTrue(bde.getResponse().readEntity(String.class).contains("invalid_scope"));
        } catch (Exception e) {
            e.printStackTrace();;
            fail("Unexpected exception.");
        }
    }
}
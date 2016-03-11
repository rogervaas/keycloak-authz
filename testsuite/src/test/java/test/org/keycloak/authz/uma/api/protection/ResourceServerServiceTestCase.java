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
import org.keycloak.authz.client.representation.ResourceServerRepresentation;
import org.keycloak.authz.client.resource.ResourceServerResource;
import test.org.keycloak.authz.uma.api.ErrorRepresentation;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.core.Response;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class ResourceServerServiceTestCase extends AbstractProtectionTestCase {

    @Test
    public void testCreate() {
        AuthzClient.AdminClient admin = this.authzClient.admin("admin", "admin", "admin-cli");
        ResourceServerResource resourceServer = admin.resourceServer();
        ResourceServerRepresentation server = new ResourceServerRepresentation();

        server.setClientId(this.clientApplication.getId());

        ResourceServerRepresentation newResrouceServer = resourceServer.create(server);

        newResrouceServer = resourceServer.findById(newResrouceServer.getId());

        assertNotNull(newResrouceServer);
        assertNotNull(newResrouceServer.getId());
        assertEquals(this.clientApplication.getId(), newResrouceServer.getClientId());
    }

    @Test
    public void testCreateInvalidClientId() {
        AuthzClient.AdminClient admin = this.authzClient.admin("admin", "admin", "admin-cli");
        ResourceServerResource resourceServer = admin.resourceServer();
        ResourceServerRepresentation server = new ResourceServerRepresentation();

        server.setClientId("");

        try {
            ResourceServerRepresentation response = resourceServer.create(server);
        } catch (BadRequestException bde) {
            Response response = bde.getResponse();
            ErrorRepresentation error = response.readEntity(ErrorRepresentation.class);

            assertNotNull(error);
            assertEquals(Response.Status.BAD_REQUEST.getStatusCode(), response.getStatus());
        }
    }

    @Test
    public void testUpdate() {
        AuthzClient.AdminClient admin = this.authzClient.admin("admin", "admin", "admin-cli");
        ResourceServerResource resourceServer = admin.resourceServer();
        ResourceServerRepresentation server = new ResourceServerRepresentation();

        server.setClientId(this.clientApplication.getId());

        ResourceServerRepresentation newResrouceServer = resourceServer.create(server);

        assertNotNull(newResrouceServer);

        resourceServer.update(newResrouceServer.getId(), newResrouceServer);

        ResourceServerRepresentation updated = resourceServer.findById(newResrouceServer.getId());
    }
}
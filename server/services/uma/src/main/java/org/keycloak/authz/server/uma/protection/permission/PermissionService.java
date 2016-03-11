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
package org.keycloak.authz.server.uma.protection.permission;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.server.uma.ErrorResponse;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.RealmModel;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;
import java.util.UUID;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PermissionService {

    private final RealmModel realm;
    private final ResourceServer resourceServer;
    private final Authorization authorizationManager;

    public PermissionService(RealmModel realm, ResourceServer resourceServer, Authorization authorizationManager) {
        this.realm = realm;
        this.resourceServer = resourceServer;
        this.authorizationManager = authorizationManager;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response create(PermissionRequest request) {
        String resourceSetId = request.getResourceSetId();

        if (resourceSetId == null) {
            return ErrorResponse.create("invalid_resource_set_id");
        }

        Resource resource = this.authorizationManager.getStoreFactory().getResourceStore().findById(resourceSetId);

        if (resource == null) {
            return ErrorResponse.create("nonexistent_resource_set_id");
        }

        for (String requestedScope : request.getScopes()) {
            boolean valid = false;

            for (Scope scope : resource.getScopes()) {
                if (scope.getName().equals(requestedScope)) {
                    valid = true;
                }
            }

            if (!valid) {
                return ErrorResponse.create("invalid_scope");
            }
        }

        return Response.status(Response.Status.CREATED).entity(new PermissionResponse(createPermissionTicket(request))).build();
    }

    private String createPermissionTicket(PermissionRequest request) {
        return new JWSBuilder().jsonContent(new PermissionTicket(UUID.randomUUID().toString(), request.getResourceSetId(), request.getScopes()))
                .rsa256(this.realm.getPrivateKey());
    }
}
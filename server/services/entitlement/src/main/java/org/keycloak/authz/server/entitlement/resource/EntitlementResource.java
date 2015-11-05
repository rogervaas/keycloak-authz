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
package org.keycloak.authz.server.entitlement.resource;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.keycloak.OAuthErrorException;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.Identity;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.EvaluationResult;
import org.keycloak.authz.core.policy.PolicyManager;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.GET;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class EntitlementResource {

    private final RealmModel realm;

    @Context
    private Authorization authorizationManager;

    @Context
    private Identity identity;

    EntitlementResource(RealmModel realm) {
        this.realm = realm;
    }

    @GET
    @Produces("application/json")
    public Response resource() {
        if (!identity.hasRole("kc-entitlement")) {
            throw new ErrorResponseException(OAuthErrorException.INVALID_SCOPE, "Requires kc-entitlement scope.", Response.Status.FORBIDDEN);
        }

        List<ResourcePermission> permissions = new ArrayList<>();
        ResourceServer resourceServer = this.authorizationManager.getStoreFactory().resourceServer().findByClient(identity.getResourceServerId());
        List<Resource> resources = this.authorizationManager.getStoreFactory().resource().findByServer(resourceServer.getId());
        resources.forEach(resource -> permissions.add(new ResourcePermission(resource, resource.getScopes())));

        PolicyManager policyManager = this.authorizationManager.getPolicyManager();
        List<EvaluationResult> results = policyManager.evaluate(new DefaultEvaluationContext(identity, this.realm, permissions, (name, values) -> false));

        Map<String, String> response = new HashMap<>();

        response.put("entitlement_token", createEntitlementToken(results.stream().map((EvaluationResult result) -> {
            ResourcePermission permission = result.getPermission();
            Resource resource = permission.getResource();
            Set<String> scopes = new HashSet<>();

            scopes.addAll(resource.getScopes().stream().map(Scope::getName).collect(Collectors.toList()));

            if (EvaluationResult.PolicyResult.Status.DENIED.equals(result.getStatus())) {
                long grantCount = result.getPolicies().stream().filter(result1 -> EvaluationResult.PolicyResult.Status.GRANTED.equals(result1.getStatus())).count();

                if (grantCount == 0) {
                    return null;
                }
            }

            EntitledResource entitledResource = new EntitledResource();

            entitledResource.setId(resource.getId());
            entitledResource.setName(resource.getName());
            entitledResource.setType(resource.getType());

            result.getPolicies().forEach(result1 -> {
                if (EvaluationResult.PolicyResult.Status.DENIED.equals(result1.getStatus())) {
                    Policy policy = result1.getPolicy();

                    policy.getScopes().forEach(scope -> scopes.remove(scope.getName()));
                }
            });

            entitledResource.setScopes(scopes);

            return entitledResource;
        }).filter(resource -> resource != null).collect(Collectors.toList())));

        return Response.ok(response).build();
    }

    private String createEntitlementToken(List<EntitledResource> permissions) {
        return new JWSBuilder().jsonContent(new EntitlementToken(permissions)).rsa256(this.realm.getPrivateKey()
        );
    }
}

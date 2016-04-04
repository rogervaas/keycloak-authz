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
package org.keycloak.authz.server.admin.resource;

import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.evaluation.DecisionResultCollector;
import org.keycloak.authz.core.policy.evaluation.Result;
import org.keycloak.authz.server.admin.resource.representation.PolicyEvaluationRequest;
import org.keycloak.authz.server.admin.resource.representation.PolicyEvaluationResponse;
import org.keycloak.authz.server.services.common.KeycloakExecutionContext;
import org.keycloak.authz.server.services.common.KeycloakIdentity;
import org.keycloak.authz.server.services.common.util.Permissions;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.TokenManager;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Produces;
import javax.ws.rs.container.AsyncResponse;
import javax.ws.rs.container.Suspended;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluateResource {

    private final RealmModel realm;
    private final ThreadFactory threadFactory;

    @Context
    private Authorization authorization;

    @Context
    private KeycloakSession keycloakSession;

    @Context
    private HttpRequest httpRequest;

    private final ResourceServer resourceServer;

    public PolicyEvaluateResource(RealmModel realm, ResourceServer resourceServer, ThreadFactory threadFactory) {
        this.realm = realm;
        this.resourceServer = resourceServer;
        this.threadFactory = threadFactory;
    }

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public void evaluate(PolicyEvaluationRequest representation, @Suspended AsyncResponse asyncResponse) {
        EvaluationContext evaluationContext = createEvaluationContext(representation);

        this.authorization.evaluators().schedule(createPermissions(representation, evaluationContext), evaluationContext, Executors.newSingleThreadExecutor(this.threadFactory))
                .evaluate(new DecisionResultCollector() {
                    @Override
                    protected void onComplete(List<Result> results) {
                        KeycloakSession keycloakSession = ResteasyProviderFactory.getContextData(KeycloakSession.class);

                        try {
                            asyncResponse.resume(Response.ok(PolicyEvaluationResponse.build(realm, results, resourceServer, authorization, keycloakSession)).build());
                        } catch (Throwable cause) {
                            asyncResponse.resume(cause);
                        }
                    }

                    @Override
                    public void onError(Throwable cause) {
                        asyncResponse.resume(cause);
                    }
                });
    }

    public EvaluationContext createEvaluationContext(final PolicyEvaluationRequest representation) {
        return new KeycloakExecutionContext(createIdentity(representation), this.realm) {
            @Override
            public Attributes getAttributes() {
                Map<String, Collection<String>> attributes = new HashMap<>(super.getAttributes().toMap());

                Map<String, String> givenAttributes = representation.getContext().get("attributes");

                givenAttributes.forEach((key, entryValue) -> {
                    if (entryValue != null) {
                        List<String> values = new ArrayList();

                        for (String value : entryValue.split(",")) {
                            values.add(value);
                        }

                        attributes.put(key, values);
                    }
                });

                return Attributes.from(attributes);
            }
        };
    }

    public List<ResourcePermission> createPermissions(PolicyEvaluationRequest representation, EvaluationContext evaluationContext) {
        if (representation.isEntitlements()) {
            return Permissions.all(this.resourceServer, evaluationContext.getIdentity(), this.authorization);
        }

        return representation.getResources().stream().flatMap((Function<PolicyEvaluationRequest.Resource, Stream<ResourcePermission>>) resource -> {
            Set<String> givenScopes = resource.getScopes();

            if (givenScopes == null) {
                givenScopes = new HashSet();
            }

            List<Scope> scopes = givenScopes.stream().map(scopeName -> authorization.getStoreFactory().getScopeStore().findByName(scopeName)).collect(Collectors.toList());

            if (resource.getId() != null) {
                Resource resourceModel = authorization.getStoreFactory().getResourceStore().findById(resource.getId());
                return Stream.of(new ResourcePermission(resourceModel, scopes));
            } else if (resource.getType() != null) {
                return authorization.getStoreFactory().getResourceStore().findByType(resource.getType()).stream().map(resource1 -> new ResourcePermission(resource1, scopes));
            } else {
                return scopes.stream().map(scope -> new ResourcePermission(null, Arrays.asList(scope)));
            }
        }).collect(Collectors.toList());
    }

    public KeycloakIdentity createIdentity(PolicyEvaluationRequest representation) {
        AccessToken accessToken = new AccessToken();

        accessToken.subject(representation.getUserId());
        accessToken.issuedFor(representation.getClientId());
        accessToken.audience(representation.getClientId());
        accessToken.issuer(Urls.realmIssuer(this.keycloakSession.getContext().getUri().getBaseUri(), realm.getName()));

        Map<String, Object> claims = accessToken.getOtherClaims();
        Map<String, String> givenAttributes = representation.getContext().get("attributes");

        if (givenAttributes != null) {
            givenAttributes.forEach((key, value) -> {
                claims.put(key, Arrays.asList(value));
            });
        }

        UserModel userModel = keycloakSession.users().getUserById(accessToken.getSubject(), realm);

        if (userModel != null) {
            Set<RoleModel> roleMappings = userModel.getRoleMappings();

            accessToken.setRealmAccess(new AccessToken.Access());

            roleMappings.stream().map(RoleModel::getName).forEach(roleName -> accessToken.getRealmAccess().addRole(roleName));

            String clientId = representation.getClientId();

            if (clientId != null) {
                ClientModel clientModel = this.realm.getClientById(clientId);

                accessToken.addAccess(clientModel.getClientId());

                userModel.getClientRoleMappings(clientModel).stream().map(RoleModel::getName).forEach(roleName -> accessToken.getResourceAccess(clientModel.getClientId()).addRole(roleName));

                //TODO: would be awesome if we could transform the access token using the configured protocol mappers. Tried, but without a clientSession and userSession is tuff.
            }
        }

        return new KeycloakIdentity(accessToken, this.realm);
    }
}

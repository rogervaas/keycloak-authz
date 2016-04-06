package org.keycloak.authz.server.admin.resource.util;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.server.admin.resource.ErrorCode;
import org.keycloak.authz.server.admin.resource.representation.PolicyRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceOwnerRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ResourceServerRepresentation;
import org.keycloak.authz.server.admin.resource.representation.ScopeRepresentation;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.ErrorResponseException;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Some utility methods to transform models to representations and vice-versa.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Models {

    public static ScopeRepresentation toRepresentation(Scope model) {
        ScopeRepresentation scope = new ScopeRepresentation();

        scope.setId(model.getId());
        scope.setName(model.getName());
        scope.setIconUri(model.getIconUri());
        scope.setPolicies(new ArrayList<>());

        Set<Policy> policies = new HashSet<>();

        policies.addAll(model.getPolicies());

        for (Policy policyModel : policies) {
            PolicyRepresentation policy = new PolicyRepresentation();

            policy.setId(policyModel.getId());
            policy.setName(policyModel.getName());
            policy.setType(policyModel.getType());

            if (!scope.getPolicies().contains(policy)) {
                scope.getPolicies().add(policy);
            }
        }

        return scope;
    }

    public static Scope toModel(ScopeRepresentation scope, ResourceServer resourceServer, Authorization authorizationManager) {
        Scope model = authorizationManager.getStoreFactory().getScopeStore().findByName(scope.getName());

        if (model == null) {
            model = authorizationManager.getStoreFactory().getScopeStore().create(scope.getName(), resourceServer);

            model.setIconUri(scope.getIconUri());

            authorizationManager.getStoreFactory().getScopeStore().save(model);
        }

        return model;
    }

    public static ResourceServerRepresentation toRepresentation(ResourceServer model, RealmModel realm) {
        ResourceServerRepresentation server = new ResourceServerRepresentation();

        server.setId(model.getId());
        server.setClientId(model.getClientId());
        ClientModel clientById = realm.getClientById(model.getClientId());
        server.setName(clientById.getClientId());
        server.setAllowEntitlements(model.isAllowEntitlements());
        server.setAllowRemoteResourceManagement(model.isAllowRemoteResourceManagement());
        server.setPolicyEnforcementMode(model.getPolicyEnforcementMode());

        return server;
    }

    public static ResourceServer toModel(ResourceServerRepresentation server, Authorization authorizationManager, RealmModel realm) {
        ClientModel client = realm.getClientById(server.getClientId());

        if (client == null) {
            throw new ErrorResponseException(ErrorCode.INVALID_CLIENT_ID, "Client with id [" + server.getClientId() + "] not found in realm [" + realm.getName()  + "].", Response.Status.BAD_REQUEST);
        }

        ResourceServer existingResourceServer = authorizationManager.getStoreFactory().getResourceServerStore().findByClient(client.getId());

        if (existingResourceServer != null) {
            throw new ErrorResponseException(ErrorCode.INVALID_CLIENT_ID, "Resource server already exists with client id [" + server.getClientId() + "].", Response.Status.BAD_REQUEST);
        }

        if (server.getName() == null) {
            server.setName(client.getName());
        }

        ResourceServer model = authorizationManager.getStoreFactory().getResourceServerStore().create(client.getId());

        model.setAllowEntitlements(server.isAllowEntitlements());
        model.setAllowRemoteResourceManagement(server.isAllowRemoteResourceManagement());
        model.setPolicyEnforcementMode(server.getPolicyEnforcementMode());

        return model;
    }

    public static PolicyRepresentation toRepresentation(Policy model, Authorization authorizationManager) {
        PolicyRepresentation representation = new PolicyRepresentation();

        representation.setId(model.getId());
        representation.setName(model.getName());
        representation.setDescription(model.getDescription());
        representation.setType(model.getType());
        representation.setDecisionStrategy(model.getDecisionStrategy());
        representation.setLogic(model.getLogic());
        representation.setConfig(new HashMap<>(model.getConfig()));

        List<Policy> policies = authorizationManager.getStoreFactory().getPolicyStore().findDependentPolicies(model.getId());

        representation.setDependentPolicies(policies.stream().map(new Function<Policy, PolicyRepresentation>() {
            @Override
            public PolicyRepresentation apply(Policy policy) {
                PolicyRepresentation representation1 = new PolicyRepresentation();

                representation1.setId(policy.getId());
                representation1.setName(policy.getName());

                return representation1;
            }
        }).collect(Collectors.toList()));

        return representation;
    }

    public static Policy toModel(PolicyRepresentation policy, ResourceServer resourceServer, Authorization authorizationManager) {
        Policy model = authorizationManager.getStoreFactory().getPolicyStore().create(policy.getName(), policy.getType(), resourceServer);

        model.setDescription(policy.getDescription());
        model.setDecisionStrategy(policy.getDecisionStrategy());
        model.setLogic(policy.getLogic());
        model.setConfig(policy.getConfig());

        return model;
    }

    public static ResourceRepresentation toRepresentation(Resource model, ResourceServer resourceServer, Authorization authorizationManager, RealmModel realm, KeycloakSession keycloakSession) {
        ResourceRepresentation resource = new ResourceRepresentation();

        resource.setId(model.getId());
        resource.setType(model.getType());
        resource.setName(model.getName());
        resource.setUri(model.getUri());
        resource.setIconUri(model.getIconUri());

        ResourceOwnerRepresentation owner = new ResourceOwnerRepresentation();

        owner.setId(model.getOwner());

        if (owner.getId().equals(resourceServer.getClientId())) {
            ClientModel clientModel = realm.getClientById(resourceServer.getClientId());
            owner.setName(clientModel.getClientId());
        } else {
            UserModel userModel = keycloakSession.users().getUserById(owner.getId(), realm);

            if (userModel == null) {
                throw new ErrorResponseException("invalid_owner", "Could not find the user [" + owner.getId() + "] who owns the Resource [" + resource.getId() + "].", Response.Status.BAD_REQUEST);
            }

            owner.setName(userModel.getUsername());
        }

        resource.setOwner(owner);

        resource.setScopes(model.getScopes().stream().map(model1 -> {
            ScopeRepresentation scope = new ScopeRepresentation();
            scope.setId(model1.getId());
            scope.setName(model1.getName());
            String iconUri = model1.getIconUri();
            if (iconUri != null) {
                scope.setIconUri(iconUri);
            }
            return scope;
        }).collect(Collectors.toSet()));

        resource.setPolicies(new ArrayList<>());

        Set<Policy> policies = new HashSet<>();

        policies.addAll(model.getPolicies());
        policies.addAll(authorizationManager.getStoreFactory().getPolicyStore().findByResourceType(resource.getType(), resourceServer.getId()));
        policies.addAll(authorizationManager.getStoreFactory().getPolicyStore().findByScopeName(resource.getScopes().stream().map(scope -> scope.getName()).collect(Collectors.toList()), resourceServer.getId()));

        for (Policy policyModel : policies) {
            PolicyRepresentation policy = new PolicyRepresentation();

            policy.setId(policyModel.getId());
            policy.setName(policyModel.getName());
            policy.setType(policyModel.getType());

            if (!resource.getPolicies().contains(policy)) {
                resource.getPolicies().add(policy);
            }
        }

        return resource;
    }

    public static Resource toModel(ResourceRepresentation resource, ResourceServer resourceServer, Authorization authorizationManager) {
        ResourceOwnerRepresentation owner = resource.getOwner();

        if (owner == null) {
            owner = new ResourceOwnerRepresentation();
            owner.setId(resourceServer.getClientId());
        }

        if (owner.getId() == null) {
            throw new ErrorResponseException("invalid_owner", "No owner specified for resource [" + resource.getName() + "].", Response.Status.BAD_REQUEST);
        }

        Resource model = authorizationManager.getStoreFactory().getResourceStore().create(resource.getName(), resourceServer, owner.getId());

        model.setType(resource.getType());
        model.setUri(resource.getUri());
        model.setIconUri(resource.getIconUri());

        Set<ScopeRepresentation> scopes = resource.getScopes();

        if (scopes != null) {
            scopes.stream().forEach(scope -> model.addScope(Models.toModel(scope, resourceServer, authorizationManager)));
        }

        return model;
    }
}

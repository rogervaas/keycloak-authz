package org.keycloak.authz.server.services.common.util;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.policy.evaluation.Result;
import org.keycloak.authz.server.services.common.representation.Permission;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Permissions {

    /**
     * Returns a list of permissions for all resources and scopes that belong to the given <code>resourceServer</code> and
     * <code>identity</code>.
     *
     * TODO: review once we support caches
     *
     * @param resourceServer
     * @param identity
     * @param authorization
     * @return
     */
    public static List<ResourcePermission> all(ResourceServer resourceServer, Identity identity, Authorization authorization) {
        List<ResourcePermission> permissions = new ArrayList<>();

        authorization.getStoreFactory().getResourceStore().findByOwner(resourceServer.getClientId()).stream().forEach(resource -> permissions.addAll(createResourcePermissions(resource)));
        authorization.getStoreFactory().getResourceStore().findByOwner(identity.getId()).stream().forEach(resource -> permissions.addAll(createResourcePermissions(resource)));

        List<String> scopeNames = authorization.getStoreFactory().getScopeStore().findByResourceServer(resourceServer.getId()).stream().map(Scope::getName).collect(Collectors.toList());

        authorization.getStoreFactory().getPolicyStore().findByScopeName(scopeNames, resourceServer.getId()).stream().forEach(policy -> permissions.add(new ResourcePermission(null, policy.getScopes().stream().collect(Collectors.toList()), resourceServer)));

        return permissions;
    }

    public static List<ResourcePermission> createResourcePermissions(Resource resource) {
        List<ResourcePermission> permissions = new ArrayList<>();
        List<Scope> scopes = resource.getScopes();

        permissions.add(new ResourcePermission(resource, Collections.emptyList(), resource.getResourceServer()));

        for (Scope scope : scopes) {
            permissions.add(new ResourcePermission(resource, Arrays.asList(scope), resource.getResourceServer()));
        }

        return permissions;
    }

    public static List<Permission> entitlements(List<Result> evaluation) {
        List<Permission> permissions = evaluation.stream()
                .filter(evaluationResult -> evaluationResult.getEffect().equals(Decision.Effect.PERMIT))
                .map(evaluationResult -> {
                    ResourcePermission permission = evaluationResult.getPermission();
                    return new Permission(permission.getResource().getId(), permission.getScopes().stream().map(Scope::getName).collect(Collectors.toList()));
                }).collect(Collectors.toList());

        Map<String, Permission> perms = new HashMap<>();

        permissions.forEach(permission -> {
            Permission evalPermission = perms.get(permission.getResourceSetId());

            if (evalPermission == null) {
                evalPermission = permission;
                perms.put(permission.getResourceSetId(), evalPermission);
            }

            List<String> scopes = evalPermission.getScopes();

            permission.getScopes().forEach(s -> {
                if (!scopes.contains(s)) {
                    scopes.add(s);
                }
            });
        });

        return perms.values().stream().collect(Collectors.toList());
    }
}

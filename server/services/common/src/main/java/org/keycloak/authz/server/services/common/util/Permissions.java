package org.keycloak.authz.server.services.common.util;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.permission.ResourcePermission;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
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

        authorization.getStoreFactory().getPolicyStore().findByScopeName(scopeNames, resourceServer.getId()).stream().forEach(policy -> permissions.add(new ResourcePermission(null, policy.getScopes().stream().collect(Collectors.toList()))));

        return permissions;
    }

    public static List<ResourcePermission> createResourcePermissions(Resource resource) {
        List<ResourcePermission> permissions = new ArrayList<>();
        List<Scope> scopes = resource.getScopes();

        permissions.add(new ResourcePermission(resource, Collections.emptyList()));

        for (Scope scope : scopes) {
            permissions.add(new ResourcePermission(resource, Arrays.asList(scope)));
        }

        return permissions;
    }
}

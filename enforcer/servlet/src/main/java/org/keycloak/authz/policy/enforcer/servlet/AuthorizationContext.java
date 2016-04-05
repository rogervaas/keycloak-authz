package org.keycloak.authz.policy.enforcer.servlet;

import org.keycloak.authz.client.representation.Permission;
import org.keycloak.authz.client.representation.RequestingPartyToken;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationContext {

    private final RequestingPartyToken authzToken;
    private final List<PathHolder> paths;
    private final String authzTokenString;

    public AuthorizationContext(RequestingPartyToken authzToken, String authzTokenString, List<PathHolder> paths) {
        this.authzToken = authzToken;
        this.authzTokenString = authzTokenString;
        this.paths = paths;
    }

    RequestingPartyToken getAuthzToken() {
        return this.authzToken;
    }

    public boolean hasPermission(String resourceName, String scopeName) {
        for (Permission permission : authzToken.getPermissions()) {
            for (PathHolder pathHolder : this.paths) {
                if (pathHolder.getId().equals(permission.getResourceSetId())) {
                    if (permission.getScopes().contains(scopeName)) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public boolean hasPermission(String resourceName) {
        for (Permission permission : authzToken.getPermissions()) {
            for (PathHolder pathHolder : this.paths) {
                if (pathHolder.getId().equals(permission.getResourceSetId())) {
                    return true;
                }
            }
        }

        return false;
    }

    public String getAuthzTokenString() {
        return this.authzTokenString;
    }

    public List<Permission> getPermissions() {
        return this.authzToken.getPermissions();
    }
}

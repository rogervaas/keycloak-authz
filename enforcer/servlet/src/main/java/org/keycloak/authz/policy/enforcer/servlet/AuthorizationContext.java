package org.keycloak.authz.policy.enforcer.servlet;

import org.keycloak.authz.client.representation.Permission;
import org.keycloak.authz.client.representation.RequestingPartyToken;
import org.keycloak.authz.policy.enforcer.servlet.Configuration.PathConfig;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class AuthorizationContext {

    private final RequestingPartyToken authzToken;
    private final List<PathConfig> paths;
    private final String authzTokenString;

    AuthorizationContext(RequestingPartyToken authzToken, String authzTokenString, List<PathConfig> paths) {
        this.authzToken = authzToken;
        this.authzTokenString = authzTokenString;
        this.paths = paths;
    }

    public boolean hasPermission(String resourceName, String scopeName) {
        for (Permission permission : authzToken.getPermissions()) {
            for (PathConfig pathHolder : this.paths) {
                if (pathHolder.getName().equals(resourceName)) {
                    if (pathHolder.getId().equals(permission.getResourceSetId())) {
                        if (permission.getScopes().contains(scopeName)) {
                            return true;
                        }
                    }
                }
            }
        }

        return false;
    }

    public boolean hasPermission(String resourceName) {
        for (Permission permission : authzToken.getPermissions()) {
            for (PathConfig pathHolder : this.paths) {
                if (pathHolder.getName().equals(resourceName)) {
                    if (pathHolder.getId().equals(permission.getResourceSetId())) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    public List<Permission> getPermissions() {
        return this.authzToken.getPermissions();
    }

    String getAuthzTokenString() {
        return this.authzTokenString;
    }

    RequestingPartyToken getAuthzToken() {
        return this.authzToken;
    }
}

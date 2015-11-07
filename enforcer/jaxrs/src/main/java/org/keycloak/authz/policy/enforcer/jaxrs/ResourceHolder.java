package org.keycloak.authz.policy.enforcer.jaxrs;

import org.keycloak.authz.client.representation.RequestingPartyToken;
import org.keycloak.authz.client.representation.ResourceRepresentation;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class ResourceHolder {

    private final ResourceRepresentation resource;
    private Set<RequestingPartyToken> permissions = new LinkedHashSet<>();

    ResourceHolder(Class<?> resourceType, ResourceRepresentation resource) {
        this.resource = resource;
    }

    ResourceRepresentation getResource() {
        return this.resource;
    }

    public Set<RequestingPartyToken> getPermissions() {
        return this.permissions;
    }
}

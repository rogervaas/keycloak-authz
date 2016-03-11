package org.keycloak.authz.policy.enforcer.jaxrs;

import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.authz.policy.enforcer.jaxrs.annotation.ProtectedResource;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Provider
public class AuthorizationDynamicFeature implements DynamicFeature {

    private final Map<Class<?>, Set<ResourceHolder>> protectedResources = new HashMap<>();
    private final AuthzClient.ProtectionClient protectionClient;
    private final AuthorizationEnforcementFilter authorizationEnforcer;

    public AuthorizationDynamicFeature() {
        this.protectionClient = AuthzClient.create().protection();
        this.authorizationEnforcer = new AuthorizationEnforcementFilter(this.protectedResources);
    }

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        Class<?> resourceClass = resourceInfo.getResourceClass();
        ProtectedResource protectedResource = resourceClass.getAnnotation(ProtectedResource.class);

        if (protectedResource != null) {
            try {
                Set<ResourceHolder> holders = this.protectedResources.get(resourceClass);

                if (holders == null) {
                    holders = new LinkedHashSet<>();
                    this.protectedResources.put(resourceClass, holders);
                }

                for (ResourceHolder holder : holders) {
                    if (holder.getResource().getName().equals(protectedResource.name())) {
                        context.register(this.authorizationEnforcer);
                        return;
                    }
                }

                holders.add(new ResourceHolder(resolveResourceId(protectedResource)));
            } catch (WebApplicationException cre) {
                throw new RuntimeException("Could not register protected resource. Server returned: [" + cre.getResponse().readEntity(String.class), cre);
            } catch (Exception e) {
                throw new RuntimeException("Unexpected error registering protected resources.", e);
            }
        }
    }

    private ResourceRepresentation resolveResourceId(ProtectedResource protectedResource) {
        Set<String> search = this.protectionClient.resource().search("name=" + protectedResource.name());

        if (search.isEmpty()) {
            if (!protectedResource.create()) {
                throw new RuntimeException("Resource [" + protectedResource.name() + "] does not exist in the server. Resource is not configured for remote registration.");
            }

            Set<ScopeRepresentation> scopes = Arrays.asList(protectedResource.scopes()).stream()
                    .map(protectedScope -> new ScopeRepresentation(protectedScope.name(), protectedScope.uri()))
                    .collect(Collectors.toSet());

            return new ResourceRepresentation(protectedResource.name(), scopes, protectedResource.uri(), protectedResource.type());
        }

        return this.protectionClient.resource().findById(search.iterator().next()).getResourceDescription();
    }
}

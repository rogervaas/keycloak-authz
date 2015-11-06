package org.keycloak.authz.policy.enforcer.jaxrs;

import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Provider
public class AuthorizationDynamicFeature implements DynamicFeature {

    private final AuthzClient.ProtectionClient protectionClient;
    private final Map<Class, String> resourceIds = new HashMap<>();

    public AuthorizationDynamicFeature() {
        this.protectionClient = createProtectionClient();
    }

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext context) {
        Class<?> resourceClass = resourceInfo.getResourceClass();
        ProtectedResource protectedResource = resourceClass.getAnnotation(ProtectedResource.class);

        if (protectedResource != null) {
            try {
                Set<String> search = this.protectionClient.resource().search("name=" + protectedResource.name());

                if (search.isEmpty()) {
                    HashSet<ScopeRepresentation> scopes = new HashSet<>();

                    for (ProtectedScope protectedScope : protectedResource.scopes()) {
                        scopes.add(new ScopeRepresentation(protectedScope.name(), protectedScope.uri()));
                    }

                    RegistrationResponse response = this.protectionClient.resource().create(
                            new ResourceRepresentation(protectedResource.name(), scopes, protectedResource.uri(), protectedResource.type())
                    );

                    this.resourceIds.put(resourceInfo.getResourceClass(), response.getId());
                } else {
                    this.resourceIds.put(resourceInfo.getResourceClass(), search.iterator().next());
                }
            } catch (WebApplicationException cre) {
                throw new RuntimeException("Could not register protected resource. Server returned: [" + cre.getResponse().readEntity(String.class), cre);
            } catch (Exception e) {
                throw new RuntimeException("Unexpected error registering protected resources.", e);
            }
        }

        context.property("resourceIds", this.resourceIds);
        context.register(new AuthorizationEnforcementFilter(this.resourceIds));
    }

    private AuthzClient.ProtectionClient createProtectionClient() {
        return AuthzClient.create().protection();
    }

}

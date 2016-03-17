package org.keycloak.authz.policy.provider.js;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.server.admin.resource.PolicyProviderAdminResource;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderAdminResource.class)
public class TimePolicyAdminResource implements PolicyProviderAdminResource {

    @Override
    public String getType() {
        return "time";
    }

    @Override
    public void init(ResourceServer resourceServer) {
    }

    @Override
    public void create(Policy policy) {
    }

    @Override
    public void update(Policy policy) {
    }

    @Override
    public void remove(Policy policy) {
    }
}

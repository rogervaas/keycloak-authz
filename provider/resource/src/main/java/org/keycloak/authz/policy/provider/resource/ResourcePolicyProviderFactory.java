package org.keycloak.authz.policy.provider.resource;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.spi.PolicyProvider;
import org.keycloak.authz.core.policy.spi.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderFactory.class)
public class ResourcePolicyProviderFactory implements PolicyProviderFactory {

    @Override
    public String getName() {
        return "Resource-Based";
    }

    @Override
    public String getGroup() {
        return "Permission";
    }

    @Override
    public String getType() {
        return "resource";
    }

    @Override
    public void init(PolicyStore policyStore) {
    }

    @Override
    public PolicyProvider create(Policy policy) {
        return new ResourcePolicyProvider(policy);
    }

    @Override
    public void dispose() {
    }
}

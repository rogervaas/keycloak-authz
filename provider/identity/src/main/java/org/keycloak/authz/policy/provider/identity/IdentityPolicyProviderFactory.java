package org.keycloak.authz.policy.provider.identity;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderFactory.class)
public class IdentityPolicyProviderFactory implements PolicyProviderFactory {

    @Override
    public String getName() {
        return "User-Based";
    }

    @Override
    public String getGroup() {
        return "Identity Based";
    }

    @Override
    public String getType() {
        return "user";
    }

    @Override
    public void init(PolicyStore policyStore) {
    }

    @Override
    public PolicyProvider create(Policy policy) {
        return new IdentityPolicyProvider(policy);
    }

    @Override
    public void dispose() {
    }
}

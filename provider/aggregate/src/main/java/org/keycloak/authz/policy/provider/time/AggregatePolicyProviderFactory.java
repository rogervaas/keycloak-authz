package org.keycloak.authz.policy.provider.time;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderFactory.class)
public class AggregatePolicyProviderFactory implements PolicyProviderFactory {

    private Authorization authorization;

    @Override
    public String getName() {
        return "Aggregate";
    }

    @Override
    public String getGroup() {
        return "Others";
    }

    @Override
    public String getType() {
        return "aggregate";
    }

    @Override
    public void init(Authorization authorization) {
        this.authorization = authorization;
    }

    @Override
    public PolicyProvider create(Policy policy) {
        return new AggregatePolicyProvider(policy, this.authorization);
    }

    @Override
    public void dispose() {
    }
}

package org.keycloak.authz.policy.provider.js;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderFactory.class)
public class JSPolicyProviderFactory implements PolicyProviderFactory {

    @Override
    public String getName() {
        return "Javascript-Based";
    }

    @Override
    public String getGroup() {
        return "Rule Based";
    }

    @Override
    public String getType() {
        return "js";
    }

    @Override
    public void init(Authorization authorization) {
    }

    @Override
    public PolicyProvider create(Policy policy) {
        return new JSPolicyProvider(policy);
    }

    @Override
    public void dispose() {
    }
}

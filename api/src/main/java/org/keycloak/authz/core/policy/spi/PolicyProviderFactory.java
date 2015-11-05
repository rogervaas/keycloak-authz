package org.keycloak.authz.core.policy.spi;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.store.PolicyStore;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyProviderFactory {

    String getName();

    String getGroup();

    String getType();

    void init(PolicyStore policyStore);

    PolicyProvider create(Policy policy);

    void dispose();
}

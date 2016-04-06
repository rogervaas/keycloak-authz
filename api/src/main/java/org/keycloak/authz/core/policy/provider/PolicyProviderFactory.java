package org.keycloak.authz.core.policy.provider;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyProviderFactory {

    String getName();

    String getGroup();

    String getType();

    void init(Authorization authorization);

    PolicyProvider create(Policy policy);

    void dispose();
}

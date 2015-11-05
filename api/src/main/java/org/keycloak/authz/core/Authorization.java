package org.keycloak.authz.core;

import org.keycloak.authz.core.policy.PolicyManager;
import org.keycloak.authz.core.store.StoreFactory;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Authorization {

    PolicyManager getPolicyManager();
    StoreFactory getStoreFactory();
}

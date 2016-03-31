package test.org.keycloak.authz.api;

import org.keycloak.authz.core.store.PolicyStore;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.authz.core.store.ResourceStore;
import org.keycloak.authz.core.store.ScopeStore;
import org.keycloak.authz.core.store.StoreFactory;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class MapStoreFactory implements StoreFactory {

    @Override
    public ResourceStore getResourceStore() {
        return new MapResourceStore();
    }

    @Override
    public ResourceServerStore getResourceServerStore() {
        return new MapResourceServerStore();
    }

    @Override
    public ScopeStore getScopeStore() {
        return new MapScopeStore();
    }

    @Override
    public PolicyStore getPolicyStore() {
        return new MapPolicyStore();
    }
}

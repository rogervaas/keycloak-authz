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

    private final MapResourceStore resourceStore;
    private final MapResourceServerStore resourceServerStore;
    private final MapPolicyStore policyStore;
    private MapScopeStore scopeStore;

    public MapStoreFactory() {
        this.resourceStore = new MapResourceStore();
        this.resourceServerStore = new MapResourceServerStore();
        this.scopeStore = new MapScopeStore();
        this.policyStore = new MapPolicyStore();
    }

    @Override
    public ResourceStore getResourceStore() {
        return this.resourceStore;
    }

    @Override
    public ResourceServerStore getResourceServerStore() {
        return this.resourceServerStore;
    }

    @Override
    public ScopeStore getScopeStore() {
        return this.scopeStore;
    }

    @Override
    public PolicyStore getPolicyStore() {
        return this.policyStore;
    }
}

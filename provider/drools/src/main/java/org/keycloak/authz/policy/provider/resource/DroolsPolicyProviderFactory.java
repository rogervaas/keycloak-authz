package org.keycloak.authz.policy.provider.resource;

import java.util.HashMap;
import java.util.Map;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;
import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderFactory.class)
public class DroolsPolicyProviderFactory implements PolicyProviderFactory {

    private KieServices ks;
    private final Map<String, DroolsPolicy> containers = new HashMap<>();

    @Override
    public String getName() {
        return "Drools";
    }

    @Override
    public String getGroup() {
        return "Rule Based";
    }

    @Override
    public String getType() {
        return "drools";
    }

    @Override
    public void init(PolicyStore policyStore) {
        this.ks = KieServices.Factory.get();
        policyStore.findByType(getType()).forEach(this::update);
    }

    @Override
    public PolicyProvider create(Policy policy) {
        if (!this.containers.containsKey(policy.getId())) {
            update(policy);
        }

        return new DroolsPolicyProvider(this.containers.get(policy.getId()));
    }

    @Override
    public void dispose() {
        this.containers.values().forEach(DroolsPolicy::dispose);
        this.containers.clear();
    }

    void update(Policy policy) {
        remove(policy);
        this.containers.put(policy.getId(), new DroolsPolicy(this.ks, policy));
    }

    void remove(Policy policy) {
        DroolsPolicy holder = this.containers.remove(policy.getId());

        if (holder != null) {
            holder.dispose();
        }
    }

    KieContainer getKieContainer(String groupId, String artifactId, String version) {
        return this.ks.newKieContainer(this.ks.newReleaseId(groupId, artifactId, version));
    }
}

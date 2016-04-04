package test.org.keycloak.authz.api;

import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.evaluation.Evaluation;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;
import org.kohsuke.MetaInfServices;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderFactory.class)
public class StaticDecisionPolicyProviderFactory implements PolicyProviderFactory {
    @Override
    public String getName() {
        return "Statis Decision Policy Provider";
    }

    @Override
    public String getGroup() {
        return "Tests";
    }

    @Override
    public String getType() {
        return "tests-static-decision";
    }

    @Override
    public void init(PolicyStore policyStore) {

    }

    @Override
    public PolicyProvider create(Policy policy) {
        return new StaticDecisionPolicyProvider(policy);
    }

    @Override
    public void dispose() {

    }

    private class StaticDecisionPolicyProvider implements PolicyProvider {

        private final Policy policy;

        public StaticDecisionPolicyProvider(Policy policy) {
            this.policy = policy;
        }

        @Override
        public void evaluate(Evaluation evaluation) {
            if (Decision.Effect.PERMIT.equals(Decision.Effect.valueOf(this.policy.getConfig().get("EFFECT").toUpperCase()))) {
                evaluation.grant();
            } else {
                evaluation.deny();
            }
        }
    }
}

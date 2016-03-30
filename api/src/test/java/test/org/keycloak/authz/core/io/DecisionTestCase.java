package test.org.keycloak.authz.core.io;

import org.junit.Test;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.policy.io.Decision;
import org.keycloak.authz.core.policy.io.SingleThreadedEvaluation;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.PolicyStore;

import java.util.Collections;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DecisionTestCase {

    @Test
    public void test() {
        new SingleThreadedEvaluation(createEvaluationContext(), createPolicyStore(), createPolicyProviders()).evaluate(new Decision() {
            @Override
            public void onGrant(Evaluation evaluation) {
                // do something if granted
            }

            @Override
            public void onDeny(Evaluation evaluation) {
                // do something if denied
            }

            @Override
            public void onError(Throwable cause) {
                // do something in case of failure
            }

            @Override
            public void onComplete() {
                // do something once all permissions were evaluated
            }
        });
    }

    public List<PolicyProviderFactory> createPolicyProviders() {
        return Collections.emptyList();
    }

    private PolicyStore createPolicyStore() {
        return null;
    }

    public DefaultEvaluationContext createEvaluationContext() {
        return new DefaultEvaluationContext(null, null, null, null);
    }
}

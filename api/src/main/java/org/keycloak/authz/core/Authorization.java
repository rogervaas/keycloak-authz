package org.keycloak.authz.core;

import org.keycloak.authz.core.permission.evaluator.Evaluators;
import org.keycloak.authz.core.policy.evaluation.DefaultPolicyEvaluator;
import org.keycloak.authz.core.policy.evaluation.PolicyEvaluator;
import org.keycloak.authz.core.policy.provider.PolicyProviderFactory;
import org.keycloak.authz.core.store.StoreFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;
import java.util.function.Supplier;

/**
 * <p>The main contract here is the creation of {@link org.keycloak.authz.core.permission.evaluator.PermissionEvaluator} instances.  Usually
 * an application has a single {@link Authorization} instance and threads servicing client requests obtain {@link org.keycloak.authz.core.permission.evaluator.PermissionEvaluator}
 * from the {@link #evaluators()} method.
 *
 * <p>The internal state of a {@link Authorization} is immutable.  This internal state includes all of the metadata
 * used during the evaluation of policies.
 *
 * <p>Instances of this class are thread-safe and must be created using a {@link Builder}:
 *
 * <pre>
 *     Authorization authorization = Authorization.builder().build();
 * </pre>
 *
 * <p>For more information about the different configuration options, please take a look at {@link Builder} documentation.
 *
 * <p>Once created, {@link org.keycloak.authz.core.permission.evaluator.PermissionEvaluator} instances can be obtained from the {@link #evaluators()} method:
 *
 * <pre>
 *     Supplier<ResourcePermission> permissionsToEvaluate = getPermissions(); // the permissions to evaluate
 *     EvaluationContext evaluationContext = createEvaluationContext(); // the context with runtime environment information
 *     PermissionEvaluator evaluator = authorization.evaluators().from(permissionsToEvaluate, context);
 *
 *     evaluator.evaluate(new Decision() {
 *
 *         public void onDecision(Evaluation evaluation) {
 *              // do something on grant
 *         }
 *
 *     });
 * </pre>
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public final class Authorization {

    private final DefaultPolicyEvaluator policyEvaluator;

    public synchronized static final Builder builder() {
        return new Builder();
    }

    private final Supplier<StoreFactory> storeFactory;
    private final List<PolicyProviderFactory> policyProviderFactories;

    private Authorization(Supplier<StoreFactory> storeFactorySupplier) {
        this.storeFactory = storeFactorySupplier;
        this.policyProviderFactories = configurePolicyProviderFactories();
        this.policyEvaluator = new DefaultPolicyEvaluator(this);
    }

    /**
     * Returns a {@link Evaluators} instance from where {@link PolicyEvaluator} instances
     * can be obtained.
     *
     * @return a {@link Evaluators} instance
     */
    public Evaluators evaluators() {
        return new Evaluators(this.policyProviderFactories, this.policyEvaluator);
    }

    /**
     * Returns a {@link StoreFactory}.
     *
     * @return the {@link StoreFactory}
     */
    public StoreFactory getStoreFactory() {
        return this.storeFactory.get();
    }

    /**
     * Returns the registered {@link PolicyProviderFactory}.
     *
     * @return a {@link List} containing all registered {@link PolicyProviderFactory}
     */
    public List<PolicyProviderFactory> getProviderFactories() {
        return this.policyProviderFactories;
    }

    /**
     * Returns a {@link PolicyProviderFactory} given a <code>type</code>.
     *
     * @param type the type of the policy provider
     * @param <F> the expected type of the provider
     * @return a {@link PolicyProviderFactory} with the given <code>type</code>
     */
    public <F extends PolicyProviderFactory> F getProviderFactory(String type) {
        return (F) getProviderFactories().stream().filter(policyProviderFactory -> policyProviderFactory.getType().equals(type)).findFirst().orElse(null);
    }

    private List<PolicyProviderFactory> configurePolicyProviderFactories() {
        List<PolicyProviderFactory> factories = new ArrayList<>();

        ServiceLoader.load(PolicyProviderFactory.class, getClass().getClassLoader()).forEach((policyProviderFactory) -> {
            policyProviderFactory.init(this);
            factories.add(policyProviderFactory);
        });

        return factories;
    }

    /**
     * A builder that provides a fluent API to configure and create {@link Authorization} instances.
     */
    public static final class Builder {

        private Supplier<StoreFactory> storeFactorySupplier;

        private Builder() {

        }

        /**
         * A {@link Supplier} of {@link StoreFactory}.
         *
         * @param supplier a supplier of store factory
         * @return this instance
         */
        public Builder storeFactory(Supplier<StoreFactory> supplier) {
            this.storeFactorySupplier = supplier;
            return this;
        }

        /**
         * Returns a new {@link Authorization} instance based on the configuration previously provided.
         *
         * @return a new {@link Authorization} instance
         */
        public Authorization build() {
            if (this.storeFactorySupplier == null) {
                StoreFactory storeFactory = configureStoreFactory();
                this.storeFactorySupplier = () -> storeFactory;
            }

            return new Authorization(this.storeFactorySupplier);
        }

        private StoreFactory configureStoreFactory() {
            Iterator<StoreFactory> iterator = ServiceLoader.load(StoreFactory.class).iterator();

            if (!iterator.hasNext()) {
                throw new RuntimeException("No " + StoreFactory.class + " found in classpath.");
            }

            return iterator.next();
        }
    }
}

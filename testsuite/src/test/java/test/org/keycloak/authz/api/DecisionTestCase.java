package test.org.keycloak.authz.api;

import mockit.Mock;
import mockit.MockUp;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.evaluation.Evaluation;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;
import org.keycloak.authz.core.policy.evaluation.ExecutionContext;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DecisionTestCase {

    static int NUM_PERMISSIONS = 1000 * 1000 * 1;

    private RealmModel realmModel;
    private MapStoreFactory mapStoreFactory;
    private Authorization authorization;
    private Supplier<ResourcePermission> permissionSupplier;

    @Before
    public void onBefore() {
        this.mapStoreFactory = new MapStoreFactory();

        this.authorization = Authorization.builder().storeFactory(new Supplier<StoreFactory>() {
            @Override
            public StoreFactory get() {
                return mapStoreFactory;
            }
        }).build();

        this.realmModel = createRealmModel();
        this.permissionSupplier = new Supplier<ResourcePermission>() {
            int i = 0;

            @Override
            public ResourcePermission get() {
                return i++ <= NUM_PERMISSIONS ? new ResourcePermission(null, Collections.emptyList()) : null;
            }
        };
    }

    @Test
    public void test() throws Exception {
        final long start = System.nanoTime();
        CountDownLatch latch = new CountDownLatch(1);
        System.out.println("Starting ...");

        this.authorization.evaluators().from(createEvaluationContext()).evaluate(new Decision() {
            @Override
            public void onGrant(Evaluation evaluation) {
//                System.out.println("onGrant: " + evaluation.getPolicy().getName() + " / " + Thread.currentThread().getName());
            }

            @Override
            public void onDeny(Evaluation evaluation) {
//                System.out.println("onDeny: " + evaluation.getPolicy().getName() + " / " + Thread.currentThread().getName());
            }

            @Override
            public void onError(Throwable cause) {
                System.out.println("onError");
                cause.printStackTrace();
                latch.countDown();
            }

            @Override
            public void onComplete() {
                System.out.println("onComplete");
                latch.countDown();
            }
        });

        latch.await(200, TimeUnit.SECONDS);

        long endTime = System.nanoTime();
        double elapsed = endTime - start;
        double elapsedSeconds = elapsed / (1000L * 1000L * 1000L);
        double throughput = NUM_PERMISSIONS / elapsedSeconds;

        System.out.format("ops/sec    = %,d\n", (int) throughput);
        System.out.format("latency ns = %.3f%n", elapsed / (float) (NUM_PERMISSIONS));
        System.out.format("elapsed = %.3f%n", elapsedSeconds);
    }

    public EvaluationContext createEvaluationContext() {
        return new MockUp<EvaluationContext>() {
            @Mock
            public Supplier<ResourcePermission> getPermissions() {
                return permissionSupplier;
            }

            @Mock
            public Identity getIdentity() {
                return new Identity() {
                    @Override
                    public String getId() {
                        return "alice";
                    }

                    @Override
                    public Attributes getAttributes() {
                        HashMap<String, Collection<String>> attributes = new HashMap<>();

                        attributes.put("roles", Arrays.asList("user"));

                        return Attributes.from(attributes);
                    }
                };
            }

            @Mock
            public ExecutionContext getExecutionContext() {
                return () -> Attributes.EMPTY;
            }

            @Mock
            public RealmModel getRealm() {
                return realmModel;
            }

        }.getMockInstance();
    }

    public RealmModel createRealmModel() {
        return new MockUp<RealmModel>() {
            @Mock
            public RoleModel getRoleById(String id) {
                return new RoleModel() {
                    @Override
                    public String getName() {
                        return "user";
                    }

                    @Override
                    public String getDescription() {
                        return null;
                    }

                    @Override
                    public void setDescription(String description) {

                    }

                    @Override
                    public String getId() {
                        return id;
                    }

                    @Override
                    public void setName(String name) {

                    }

                    @Override
                    public boolean isScopeParamRequired() {
                        return false;
                    }

                    @Override
                    public void setScopeParamRequired(boolean scopeParamRequired) {

                    }

                    @Override
                    public boolean isComposite() {
                        return false;
                    }

                    @Override
                    public void addCompositeRole(RoleModel role) {

                    }

                    @Override
                    public void removeCompositeRole(RoleModel role) {

                    }

                    @Override
                    public Set<RoleModel> getComposites() {
                        return null;
                    }

                    @Override
                    public RoleContainerModel getContainer() {
                        return null;
                    }

                    @Override
                    public boolean hasRole(RoleModel role) {
                        return false;
                    }
                };
            }
        }.getMockInstance();
    }
}

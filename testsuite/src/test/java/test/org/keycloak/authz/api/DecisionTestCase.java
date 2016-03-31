package test.org.keycloak.authz.api;

import mockit.Mock;
import mockit.MockUp;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.policy.ExecutionContext;
import org.keycloak.authz.core.store.StoreFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DecisionTestCase {

    static int NUM_PERMISSIONS = 1000 * 1000 * 3;

    private RealmModel realmModel;
    private List<ResourcePermission> permissions;
    private MapStoreFactory mapStoreFactory;
    private Authorization authorization;

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
        this.permissions = createPermissions();
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
            public List<ResourcePermission> getAllPermissions() {
                return permissions;
            }

            @Mock
            public Identity getIdentity() {
                return new Identity() {
                    @Override
                    public String getId() {
                        return "alice";
                    }

                    @Override
                    public Map<String, List<String>> getAttributes() {
                        HashMap<String, List<String>> attributes = new HashMap<>();

                        attributes.put("scopes", Arrays.asList("user"));

                        return attributes;
                    }
                };
            }

            @Mock
            public ExecutionContext getExecutionContext() {
                return new ExecutionContext() {
                    @Override
                    public Map<String, List<String>> getAttributes() {
                        return Collections.emptyMap();
                    }
                };
            }

            @Mock
            public RealmModel getRealm() {
                return realmModel;
            }

        }.getMockInstance();
    }

    private List<ResourcePermission> createPermissions() {
        List<ResourcePermission> permissions = new ArrayList();

        for (int i = 0 ; i < NUM_PERMISSIONS; i++) {
            permissions.add(new ResourcePermission(null, Collections.emptyList()));
        }

        return permissions;
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

package test.org.keycloak.authz.api;

import mockit.Mock;
import mockit.MockUp;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.attribute.Attributes;
import org.keycloak.authz.core.identity.Identity;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.permission.ResourcePermission;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.policy.evaluation.Evaluation;
import org.keycloak.authz.core.EvaluationContext;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleContainerModel;
import org.keycloak.models.RoleModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DecisionTestCase {

    static int NUM_PERMISSIONS = 1000 * 1000 * 5;

    private MapStoreFactory mapStoreFactory;
    private Authorization authorization;
    private Supplier<ResourcePermission> permissionSupplier;

    @Before
    public void onBefore() {
        this.mapStoreFactory = new MapStoreFactory();

        ResourceServer resourceServer = this.mapStoreFactory.getResourceServerStore().create(new MockUp<ClientModel>() {

        }.getMockInstance());

        this.mapStoreFactory.getResourceServerStore().save(resourceServer);

        Resource resource = this.mapStoreFactory.getResourceStore().create("Resource A", resourceServer, "alice");

        this.mapStoreFactory.getResourceStore().save(resource);

        Policy policy = this.mapStoreFactory.getPolicyStore().create("Resource A Policy", "resource", resourceServer);

//        policy.addResource(resource);

        this.mapStoreFactory.getPolicyStore().save(policy);

        Policy droolsPolicy = this.mapStoreFactory.getPolicyStore().create("Drools Policy", "drools", resourceServer);

        this.mapStoreFactory.getPolicyStore().save(droolsPolicy);

        Map<String, String> config = new HashMap<>();

        config.put("mavenArtifactGroupId", "org.keycloak");
        config.put("mavenArtifactId", "photoz-authz-policy");
        config.put("mavenArtifactVersion", "1.0-SNAPSHOT");
        config.put("scannerPeriod", "1");
        config.put("scannerPeriodUnit", "Minutes");
        config.put("sessionName", "MainOwnerSession");

        droolsPolicy.setConfig(config);

        policy.addAssociatedPolicy(droolsPolicy);

        this.permissionSupplier = createPermissionSupplier(resource);

        this.authorization = Authorization.builder().storeFactory(() -> mapStoreFactory).build();
    }

    @Test
    public void test() throws Exception {
        final long start = System.nanoTime();
        CountDownLatch latch = new CountDownLatch(1);
        System.out.println("Starting ...");

        this.authorization.evaluators()
                .schedule(this.permissionSupplier, createExecutionContext(), Executors.newWorkStealingPool())
//                .from(this.permissionSupplier, createExecutionContext())
                .evaluate(createDecision(latch));

        latch.await(200, TimeUnit.SECONDS);

        long endTime = System.nanoTime();
        double elapsed = endTime - start;
        double elapsedSeconds = elapsed / (1000L * 1000L * 1000L);
        double throughput = NUM_PERMISSIONS / elapsedSeconds;

        System.out.format("ops/sec    = %,d\n", (int) throughput);
        System.out.format("latency ns = %.3f%n", elapsed / (float) (NUM_PERMISSIONS));
        System.out.format("elapsed = %.3f%n", elapsedSeconds);
    }

    private Decision createDecision(final CountDownLatch latch) {
        return new Decision() {
            @Override
            public void onDecision(Evaluation evaluation, Effect effect) {
                System.out.println(effect + ": " + evaluation.getPolicy().getName() + " / " + Thread.currentThread().getName());
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
        };
    }

    private RealmModel createRealmModel() {
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

    private EvaluationContext createExecutionContext() {
        return new EvaluationContext() {
            @Override
            public Identity getIdentity() {
                return createIdentity();
            }

            @Override
            public RealmModel getRealm() {
                return createRealmModel();
            }

            @Override
            public Attributes getAttributes() {
                return Attributes.EMPTY;
            }
        };
    }

    private Identity createIdentity() {
        return new Identity() {
            @Override
            public String getId() {
                return "admin";
            }

            @Override
            public Attributes getAttributes() {
                HashMap<String, Collection<String>> attributes = new HashMap<>();

                attributes.put("roles", Arrays.asList("admin"));

                return Attributes.from(attributes);
            }
        };
    }

    private Supplier<ResourcePermission> createPermissionSupplier(final Resource resource) {
        List<ResourcePermission> resourcePermissions = new ArrayList<>();

        return new Supplier<ResourcePermission>() {
            private int count = 0;

            @Override
            public ResourcePermission get() {
                if (count++ > NUM_PERMISSIONS) {
                    return null;
                }

                return new ResourcePermission(resource, Arrays.asList());
            }
        };
    }
}

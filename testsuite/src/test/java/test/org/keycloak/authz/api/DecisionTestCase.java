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
import org.keycloak.authz.core.model.ResourcePermission;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.policy.Decision;
import org.keycloak.authz.core.policy.evaluation.Evaluation;
import org.keycloak.authz.core.policy.evaluation.EvaluationContext;
import org.keycloak.authz.core.policy.evaluation.ExecutionContext;
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
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DecisionTestCase {

    static int NUM_PERMISSIONS = 1000 * 1000 * 5;

    private RealmModel realmModel;
    private MapStoreFactory mapStoreFactory;
    private Authorization authorization;
    private Identity identity;
    private ExecutionContext executionContext;
    private Stream<ResourcePermission> permissionSupplier;
    private Stream<ResourcePermission> permissionSupplier2;
    private Stream<ResourcePermission> permissionSupplier3;
    private Stream<ResourcePermission> permissionSupplier4;

    @Before
    public void onBefore() {
        this.mapStoreFactory = new MapStoreFactory();
        this.realmModel = createRealmModel();
        this.identity = new Identity() {
            @Override
            public String getId() {
                return "alice";
            }

            @Override
            public Attributes getAttributes() {
                HashMap<String, Collection<String>> attributes = new HashMap<>();

                attributes.put("roles", Arrays.asList("admin"));

                return Attributes.from(attributes);
            }
        };
        this.executionContext = () -> Attributes.EMPTY;

        ResourceServer resourceServer = this.mapStoreFactory.getResourceServerStore().create(new MockUp<ClientModel>() {

        }.getMockInstance());

        this.mapStoreFactory.getResourceServerStore().save(resourceServer);

        Resource resource = this.mapStoreFactory.getResourceStore().create("Resource A", resourceServer, "alice");

        this.mapStoreFactory.getResourceStore().save(resource);

        Policy policy = this.mapStoreFactory.getPolicyStore().create("Resource A Policy", "resource", resourceServer);

        policy.addResource(resource);

        this.mapStoreFactory.getPolicyStore().save(policy);

        Policy droolsPolicy = this.mapStoreFactory.getPolicyStore().create("Drools Policy", "drools", resourceServer);

        this.mapStoreFactory.getPolicyStore().save(droolsPolicy);

        Map<String, String> config = new HashMap<>();

        config.put("mavenArtifactGroupId", "org.keycloak");
        config.put("mavenArtifactId", "photoz-authz-policy");
        config.put("mavenArtifactVersion", "1.0-SNAPSHOT");
        config.put("scannerPeriod", "1");
        config.put("scannerPeriodUnit", "Minutes");
        config.put("sessionName", "MainAdminSession");

        droolsPolicy.setConfig(config);

        policy.addAssociatedPolicy(droolsPolicy);

        this.permissionSupplier = createPermissionSupplier(resource);
        this.permissionSupplier2 = createPermissionSupplier(resource);
        this.permissionSupplier3 = createPermissionSupplier(resource);
        this.permissionSupplier4 = createPermissionSupplier(resource);

        this.authorization = Authorization.builder().storeFactory(() -> mapStoreFactory).build();
    }

    public Stream<ResourcePermission> createPermissionSupplier(final Resource resource) {
        List<ResourcePermission> resourcePermissions = new ArrayList<>();

        for (int i = 0; i < NUM_PERMISSIONS / 4; i++) {
            resourcePermissions.add(new ResourcePermission(resource, Arrays.asList()));
        }

        return StreamSupport.stream(resourcePermissions.spliterator(), true);
    }

    @Test
    public void test() throws Exception {
        final long start = System.nanoTime();
        CountDownLatch latch = new CountDownLatch(4);
        System.out.println("Starting ...");

        this.authorization.evaluators().from(createEvaluationContext(this.permissionSupplier)).evaluate(createDecision(latch));
        this.authorization.evaluators().from(createEvaluationContext(this.permissionSupplier2)).evaluate(createDecision(latch));
        this.authorization.evaluators().from(createEvaluationContext(this.permissionSupplier3)).evaluate(createDecision(latch));
        this.authorization.evaluators().from(createEvaluationContext(this.permissionSupplier4)).evaluate(createDecision(latch));

        latch.await(200, TimeUnit.SECONDS);

        long endTime = System.nanoTime();
        double elapsed = endTime - start;
        double elapsedSeconds = elapsed / (1000L * 1000L * 1000L);
        double throughput = NUM_PERMISSIONS / elapsedSeconds;

        System.out.format("ops/sec    = %,d\n", (int) throughput);
        System.out.format("latency ns = %.3f%n", elapsed / (float) (NUM_PERMISSIONS));
        System.out.format("elapsed = %.3f%n", elapsedSeconds);
    }

    public Decision createDecision(final CountDownLatch latch) {
        return new Decision() {
            @Override
            public void onDecision(Evaluation evaluation, Effect effect) {
//                System.out.println(effect + ": " + evaluation.getPolicy().getName() + " / " + Thread.currentThread().getName());
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

    public EvaluationContext createEvaluationContext(Stream<ResourcePermission> permissionSupplier) {
        return new MockUp<EvaluationContext>() {
            @Mock
            public Stream<ResourcePermission> getPermissions() {
                return permissionSupplier;
            }

            @Mock
            public Identity getIdentity() {
                return identity;
            }

            @Mock
            public ExecutionContext getExecutionContext() {
                return executionContext;
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

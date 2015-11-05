package org.keycloak.authz.policy.provider.resource;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.server.admin.resource.PolicyProviderAdminResource;
import org.keycloak.authz.server.admin.resource.representation.PolicyRepresentation;
import org.kie.api.runtime.KieContainer;
import org.kohsuke.MetaInfServices;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@MetaInfServices(PolicyProviderAdminResource.class)
public class DroolsPolicyAdminResource implements PolicyProviderAdminResource {

    private DroolsPolicyProviderFactory provider;
    private ResourceServer resourceServer;

    @Context
    private Authorization authorizationManager;

    @Override
    public String getType() {
        return "drools";
    }

    @Override
    public void init(final ResourceServer resourceServer) {
        this.resourceServer = resourceServer;
        this.provider = authorizationManager.getPolicyManager().getProviderFactory(getType());
    }

    @Override
    public void create(Policy policy) {
        this.provider.update(policy);
    }

    @Override
    public void update(Policy policy) {
        this.provider.update(policy);
    }

    @Override
    public void remove(Policy policy) {
        this.provider.remove(policy);
    }

    @Path("/resolveModules")
    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response resolveModules(PolicyRepresentation policy) {
        return Response.ok(getContainer(policy).getKieBaseNames()).build();
    }

    @Path("/resolveSessions")
    @POST
    @Consumes("application/json")
    @Produces("application/json")
    public Response resolveSessions(PolicyRepresentation policy) {
        return Response.ok(getContainer(policy).getKieSessionNamesInKieBase(policy.getConfig().get("moduleName"))).build();
    }

    private KieContainer getContainer(PolicyRepresentation policy) {
        String groupId = policy.getConfig().get("mavenArtifactGroupId");
        String artifactId = policy.getConfig().get("mavenArtifactId");
        String version = policy.getConfig().get("mavenArtifactVersion");
        return this.provider.getKieContainer(groupId, artifactId, version);
    }
}

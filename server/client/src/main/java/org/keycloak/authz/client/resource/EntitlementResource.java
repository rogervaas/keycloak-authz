package org.keycloak.authz.client.resource;

import org.keycloak.authz.client.representation.EntitlementResponse;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Path("/entitlement")
public interface EntitlementResource {

    @GET
    @Produces("application/json")
    EntitlementResponse get(@QueryParam("resourceServerId") String resourceServerId);
}

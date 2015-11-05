package org.keycloak.authz.client.resource;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Path("/entitlement")
public interface EntitlementResource {

    @GET
    @Consumes()
    @Produces("application/json")
    Response findAll();
}

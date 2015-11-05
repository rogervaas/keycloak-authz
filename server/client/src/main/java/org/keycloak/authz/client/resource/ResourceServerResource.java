package org.keycloak.authz.client.resource;

import org.keycloak.authz.server.admin.resource.representation.ResourceServerRepresentation;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Path("/resource-server")
public interface ResourceServerResource {

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    ResourceServerRepresentation create(ResourceServerRepresentation server);

    @Path("{id}")
    @PUT
    @Consumes("application/json")
    @Produces("application/json")
    void update(@PathParam("id") String id, ResourceServerRepresentation server);

    @Path("{id}")
    @GET
    @Produces("application/json")
    ResourceServerRepresentation findById(@PathParam("id") String id);
}

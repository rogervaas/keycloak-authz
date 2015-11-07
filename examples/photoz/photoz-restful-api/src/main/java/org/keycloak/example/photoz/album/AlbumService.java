package org.keycloak.example.photoz.album;

import org.keycloak.authz.client.AuthzClient;
import org.keycloak.authz.client.representation.ResourceRepresentation;
import org.keycloak.authz.client.representation.ScopeRepresentation;
import org.keycloak.authz.policy.enforcer.jaxrs.annotation.Enforce;
import org.keycloak.authz.policy.enforcer.jaxrs.annotation.ProtectedResource;
import org.keycloak.authz.policy.enforcer.jaxrs.annotation.ProtectedScope;
import org.keycloak.example.photoz.entity.Album;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Path("/album")
@ProtectedResource(
        name = "Album Resource",
        type = "http://photoz.com/dev/resource/album",
        uri = "/album/*",
        scopes = {
            @ProtectedScope(name = AlbumService.SCOPE_ALBUM_VIEW),
            @ProtectedScope(name = AlbumService.SCOPE_ALBUM_CREATE),
            @ProtectedScope(name = AlbumService.SCOPE_ALBUM_DELETE)
        })
@Stateless
public class AlbumService {

    public static final String SCOPE_ALBUM_VIEW = "urn:photoz.com:scopes:album:view";
    public static final String SCOPE_ALBUM_CREATE = "urn:photoz.com:scopes:album:create";
    public static final String SCOPE_ALBUM_DELETE = "urn:photoz.com:scopes:album:delete";

    @PersistenceContext
    private EntityManager entityManager;

    @Context
    private SecurityContext securityContext;

    @Context
    private HttpHeaders headers;

    @POST
    @Consumes("application/json")
    @Enforce(scopes= AlbumService.SCOPE_ALBUM_CREATE)
    public Response create(Album album) {
        album.setUserId(this.securityContext.getUserPrincipal().getName());

        this.entityManager.persist(album);

        createProtectedResource(album);

        return Response.ok(album).build();
    }

    @Path("{id}")
    @DELETE
    @Enforce(uri = "/album/{id}", scopes= AlbumService.SCOPE_ALBUM_DELETE)
    public Response delete(@PathParam("id") String id) {
        Album album = this.entityManager.find(Album.class, Long.valueOf(id));

        try {
            deleteProtectedResource(album);
            this.entityManager.remove(album);
        } catch (Exception e) {
            throw new RuntimeException("Could not delete album.", e);
        }

        return Response.ok().build();
    }

    @GET
    @Produces("application/json")
    public Response findAll() {
        return Response.ok(this.entityManager.createQuery("from Album where userId = '" + this.securityContext.getUserPrincipal().getName() + "'").getResultList()).build();
    }

    @GET
    @Path("{id}")
    @Produces("application/json")
    @Enforce(uri = "/album/{id}", scopes= AlbumService.SCOPE_ALBUM_VIEW)
    public Response findById(@PathParam("id") String id) {
        List result = this.entityManager.createQuery("from Album where id = " + id).getResultList();

        if (result.isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        return Response.ok(result.get(0)).build();
    }

    private void createProtectedResource(Album album) {
        try {
            HashSet<ScopeRepresentation> scopes = new HashSet<>();

            scopes.add(new ScopeRepresentation(SCOPE_ALBUM_VIEW));
            scopes.add(new ScopeRepresentation(SCOPE_ALBUM_CREATE));
            scopes.add(new ScopeRepresentation(SCOPE_ALBUM_DELETE));

            ResourceRepresentation albumResource = new ResourceRepresentation(album.getName(), scopes, "/album/" + album.getId(), "http://photoz.com/dev/resource/album");

            albumResource.setOwner(album.getUserId());

            AuthzClient.create().protection().resource().create(albumResource);
        } catch (Exception e) {
            throw new RuntimeException("Could not register protected resource.", e);
        }
    }

    private void deleteProtectedResource(Album album) {
        String uri = "/album/" + album.getId();

        try {

            AuthzClient.ProtectionClient protection = AuthzClient.create().protection();
            Set<String> search = protection.resource().search("uri=" + uri);

            if (search.isEmpty()) {
                throw new RuntimeException("Could not find protected resource with URI [" + uri);
            }

            protection.resource().delete(search.iterator().next());
        } catch (Exception e) {
            throw new RuntimeException("Could not search protected resource.", e);
        }
    }
}

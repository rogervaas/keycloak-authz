/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2015 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.authz.client.resource;

import org.keycloak.authz.client.representation.RegistrationResponse;
import org.keycloak.authz.client.representation.ResourceRepresentation;

import java.util.Set;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Path("/resource_set")
public interface ProtectedResource {

    @POST
    @Consumes("application/json")
    @Produces("application/json")
    RegistrationResponse create(ResourceRepresentation resource);

    @Path("/{id}")
    @GET
    @Consumes()
    @Produces("application/json")
    RegistrationResponse findById(@PathParam("id") String id);

    @GET
    @Consumes()
    @Produces("application/json")
    Set<String> findAll();

    @Path("/{id}")
    @DELETE
    @Consumes()
    void delete(@PathParam("id") String id);

    @DELETE
    @Consumes()
    void deleteAll();

    @Path("/search")
    @GET
    @Consumes()
    @Produces("application/json")
    Set<String> search(@QueryParam("filter") String filter);
}

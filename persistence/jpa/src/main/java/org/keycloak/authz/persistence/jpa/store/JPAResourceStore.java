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
package org.keycloak.authz.persistence.jpa.store;

import java.util.Arrays;
import java.util.List;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ResourceStore;
import org.keycloak.authz.persistence.jpa.entity.ResourceEntity;
import org.keycloak.authz.persistence.jpa.entity.ResourceServerEntity;

import javax.persistence.EntityManager;
import javax.persistence.Query;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceStore implements ResourceStore {

    private final EntityManager entityManager;

    public JPAResourceStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Resource create(String name, ResourceServer resourceServer, String owner) {
        if (!(resourceServer instanceof ResourceServerEntity)) {
            throw new RuntimeException("Unexpected type [" + resourceServer.getClass() + "].");
        }

        ResourceEntity entity = new ResourceEntity();

        entity.setName(name);
        entity.setResourceServer((ResourceServerEntity) resourceServer);
        entity.setOwner(owner);

        return entity;
    }

    @Override
    public void save(Resource resource) {
        if (!(resource instanceof ResourceEntity)) {
            throw new RuntimeException("Unexpected type [" + resource.getClass() + "].");
        }

        ResourceEntity entity = (ResourceEntity) resource;

        if (entity.getId() == null) {
            entity.setId(Identifiers.generateId());
            this.entityManager.persist(entity);
        } else {
            this.entityManager.merge(entity);
        }
    }

    @Override
    public void delete(String id) {
        this.entityManager.remove(findById(id));
    }

    @Override
    public Resource findById(String id) {
        return entityManager.find(ResourceEntity.class, id);
    }

    @Override
    public List<Resource> findByOwner(String ownerId) {
        Query query = entityManager.createQuery("from ResourceEntity where owner = :ownerId");

        query.setParameter("ownerId", ownerId);

        return query.getResultList();
    }

    @Override
    public List findByServer(String resourceServerId) {
        Query query = entityManager.createQuery("from ResourceEntity where resourceServer.id = :serverId");

        query.setParameter("serverId", resourceServerId);

        return query.getResultList();
    }

    @Override
    public List<Resource> findByScope(String... id) {
        Query query = entityManager.createQuery("from ResourceEntity r inner join r.scopes s where s.id in (:scopeIds)");

        query.setParameter("scopeIds", Arrays.asList(id));

        return query.getResultList();
    }

    @Override
    public Resource findByName(String name) {
        Query query = entityManager.createQuery("from ResourceEntity where name = :name");

        query.setParameter("name", name);

        List<Resource> result = query.getResultList();

        if (!result.isEmpty()) {
            return result.get(0);
        }

        return null;
    }

    @Override
    public List<Resource> findByType(String type) {
        Query query = entityManager.createQuery("from ResourceEntity where type = :type");

        query.setParameter("type", type);

        return query.getResultList();
    }
}

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

import java.util.List;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.Scope;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ScopeStore;
import org.keycloak.authz.persistence.jpa.entity.ResourceServerEntity;
import org.keycloak.authz.persistence.jpa.entity.ScopeEntity;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAScopeStore implements ScopeStore {

    private final EntityManager entityManager;

    public JPAScopeStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Scope create(final String name, final ResourceServer resourceServer) {
        ScopeEntity entity = new ScopeEntity();

        entity.setName(name);
        entity.setResourceServer((ResourceServerEntity) resourceServer);

        return entity;
    }

    @Override
    public void save(Scope scope) {
        if (!(scope instanceof ScopeEntity)) {
            throw new RuntimeException("Unexpected type [" + scope.getClass() + "].");
        }

        ScopeEntity entity = (ScopeEntity) scope;

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
    public Scope findById(String id) {
        return entityManager.find(ScopeEntity.class, id);
    }

    @Override
    public Scope findByName(String name) {
        try {
            Query query = entityManager.createQuery("from ScopeEntity where name = :name");

            query.setParameter("name", name);

            return (Scope) query.getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    @Override
    public List<Scope> findByServer(final String serverId) {
        Query query = entityManager.createQuery("from ScopeEntity where resourceServer.id = :serverId");

        query.setParameter("serverId", serverId);

        return query.getResultList();
    }
}

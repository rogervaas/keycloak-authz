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

import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.ResourceServerStore;
import org.keycloak.authz.persistence.jpa.entity.ResourceServerEntity;

import javax.persistence.EntityManager;
import javax.persistence.Query;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAResourceServerStore implements ResourceServerStore {

    private final EntityManager entityManager;

    public JPAResourceServerStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public ResourceServer create(String clientId) {
        ResourceServerEntity entity = new ResourceServerEntity();

        entity.setClientId(clientId);

        return entity;
    }

    @Override
    public void save(ResourceServer resourceServer) {
        if (!(resourceServer instanceof ResourceServerEntity)) {
            throw new RuntimeException("Unexpected type [" + resourceServer.getClass() + "].");
        }

        ResourceServerEntity entity = (ResourceServerEntity) resourceServer;

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
    public ResourceServer findById(String id) {
        return entityManager.find(ResourceServerEntity.class, id);
    }

    @Override
    public ResourceServer findByClient(final String clientId) {
        Query query = entityManager.createQuery("from ResourceServerEntity where clientId = :clientId");

        query.setParameter("clientId", clientId);
        List result = query.getResultList();

        if (result.isEmpty()) {
            return null;
        }

        return (ResourceServer) result.get(0);
    }
}

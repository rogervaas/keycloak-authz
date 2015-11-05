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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.model.util.Identifiers;
import org.keycloak.authz.core.store.PolicyStore;
import org.keycloak.authz.persistence.jpa.entity.PolicyEntity;
import org.keycloak.authz.persistence.jpa.entity.ResourceServerEntity;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.Query;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JPAPolicyStore implements PolicyStore {

    private final EntityManager entityManager;

    public JPAPolicyStore(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    @Override
    public Policy create(String name, String type, ResourceServer resourceServer) {
        PolicyEntity entity = new PolicyEntity();

        entity.setName(name);
        entity.setType(type);
        entity.setResourceServer((ResourceServerEntity) resourceServer);

        return entity;
    }

    @Override
    public void save(Policy policy) {
        if (!(policy instanceof PolicyEntity)) {
            throw new RuntimeException("Unexpected type [" + policy.getClass() + "].");
        }

        PolicyEntity entity = (PolicyEntity) policy;

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
    public Policy findById(String id) {
        return this.entityManager.find(PolicyEntity.class, id);
    }

    @Override
    public Policy findByName(String name) {
        try {
            Query query = entityManager.createQuery("from PolicyEntity where name = :name");

            query.setParameter("name", name);

            return (Policy) query.getSingleResult();
        } catch (NoResultException nre) {
            return null;
        }
    }

    @Override
    public List<Policy> findByServer(final String serverId) {
        Query query = entityManager.createQuery("from PolicyEntity where resourceServer.id = :serverId");

        query.setParameter("serverId", serverId);

        return query.getResultList();
    }

    @Override
    public List<Policy> findByResource(final String resourceId) {
        Query query = entityManager.createQuery("select p from PolicyEntity p inner join p.resources r where r.id = :resourceId");

        query.setParameter("resourceId", resourceId);

        return query.getResultList();
    }

    @Override
    public List<Policy> findByResourceType(final String resourceType) {
        List<Policy> policies = new ArrayList<>();
        Query query = entityManager.createQuery("from PolicyEntity");
        List<Policy> models = query.getResultList();

        for (Policy policy : models) {
            String defaultType = policy.getConfig().get("defaultResourceType");

            if (defaultType != null && defaultType.equals(resourceType) && policy.getResources().isEmpty()) {
                policies.add(policy);
            }
        }

        return policies;
    }

    @Override
    public List<Policy> findByScopeName(List<String> scopeNames) {
        Query query = entityManager.createQuery("select p from PolicyEntity p inner join p.scopes s where s.name in (:scopeNames) and p.resources is empty group by p.id order by p.name");

        query.setParameter("scopeNames", scopeNames);

        return query.getResultList();
    }

    @Override
    public List<Policy> findByType(String type) {
        Query query = entityManager.createQuery("select p from PolicyEntity p where p.type = :type");

        query.setParameter("type", type);

        return query.getResultList();
    }

    @Override
    public List<Policy> findDependentPolicies(String policyId) {
        Query query = entityManager.createQuery("select p from PolicyEntity p inner join p.associatedPolicies ap where ap.id in (:policyId)");

        query.setParameter("policyId", Arrays.asList(policyId));

        return query.getResultList();
    }
}

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
package org.keycloak.authz.core;

import java.util.List;
import java.util.Map;

/**
 * <p>Represents an security identity, which can be a person or non-person entity.
 *
 * <p>An identity plays an important role during the evaluation of policies as they represent the entity which one or more permissions
 * should be granted, or not. Beside that they also provides additional information and attributes that can be relevant to the different
 * access control methods involved.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Identity {

    /**
     * Returns the unique identifier of the identity.
     *
     * @return the unique identifier of the identity
     */
    String getId();

    String getResourceServerId();

    default boolean hasRole(String role) {
        List<String> roles = getAttributes().get("roles");
        return roles != null && roles.contains(role);
    }

    Map<String, List<String>> getAttributes();

    boolean isResourceServer();
}

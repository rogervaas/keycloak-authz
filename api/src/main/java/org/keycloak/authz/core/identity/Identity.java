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
package org.keycloak.authz.core.identity;

import java.util.List;
import java.util.Map;

/**
 * <p>Represents a security identity, which can be a person or non-person entity that was previously authenticated.
 *
 * <p>An {@link Identity} plays an important role during the evaluation of policies as they represent the entity to which one or more permissions
 * should be granted or not, providing additional information and attributes that can be relevant to the different
 * access control methods involved during the evaluation of policies.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Identity {

    /**
     * Returns the unique identifier of this identity.
     *
     * @return the unique identifier of this identity
     */
    String getId();

    /**
     * Returns the attributes or claims for this identity.
     *
     * @return the attributes or claims for this identity
     */
    Map<String, List<String>> getAttributes();

    /**
     * Indicates if this identity has a given <code>scopes</code>.
     *
     * @param role the name of the role
     *
     * @return true if the identity has the given role. Otherwise, it returns false.
     */
    default boolean hasScope(String role) {
        List<String> roles = getAttributes().get("scopes");
        return roles != null && roles.contains(role);
    }
}

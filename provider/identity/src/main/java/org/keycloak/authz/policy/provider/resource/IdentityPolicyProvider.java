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
package org.keycloak.authz.policy.provider.resource;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.EvaluationContext;
import org.keycloak.authz.core.policy.spi.PolicyProvider;
import org.keycloak.models.RoleModel;
import org.keycloak.util.JsonSerialization;

import java.io.IOException;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class IdentityPolicyProvider implements PolicyProvider {

    private final Policy policy;

    public IdentityPolicyProvider(Policy policy) {
        this.policy = policy;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        EvaluationContext context = evaluation.getContext();
        String users = policy.getConfig().get("users");
        String roles = policy.getConfig().get("roles");

        boolean userGranted = users == null;
        boolean roleGranted = roles == null;

        if (users != null) {
            try {
                String[] userIds = JsonSerialization.readValue(users.getBytes(), String[].class);

                if (userIds.length == 0) {
                    userGranted = true;
                } else {
                    for (String userId : userIds) {
                        if (context.getIdentity().getId().equals(userId)) {
                            userGranted = true;
                            break;
                        }
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException("Could not parse users [" + users + "] from policy config [" + policy.getId() + ".", e);
            }
        }

        if (roles != null) {
            try {
                String[] roleIds = JsonSerialization.readValue(roles.getBytes(), String[].class);

                if (roleIds.length == 0) {
                    roleGranted = true;
                } else {
                    for (String roleId : roleIds) {
                        RoleModel role = context.getRealm().getRoleById(roleId);

                        if (role != null && context.getIdentity().hasRole(role.getName())) {
                            roleGranted = true;
                            break;
                        }
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException("Could not parse roles [" + roles + "] from policy config [" + policy.getId() + ".", e);
            }
        }

        if (userGranted && roleGranted) {
            evaluation.grant();
        }
    }
}

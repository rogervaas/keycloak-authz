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
package org.keycloak.authz.policy.provider.js;

import org.keycloak.authz.core.model.Policy;
import org.keycloak.authz.core.policy.Advice;
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.provider.PolicyProvider;
import org.keycloak.common.util.Time;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class TimePolicyProvider implements PolicyProvider {

    private final Policy policy;

    public TimePolicyProvider(Policy policy) {
        this.policy = policy;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        boolean isGranted = true;
        List<Advice> advices = new ArrayList<>();
        String expires = this.policy.getConfig().get("exp");

        if (expires != null) {
            if (Time.currentTime() < Integer.parseInt(expires)) {
                isGranted = false;
            } else {
                advices.add(Advice.withCategory("time").addProperty("exp", expires).build());
            }
        }

        String notBefore = this.policy.getConfig().get("nbf");

        if (notBefore != null) {
            if (Time.currentTime() < Integer.parseInt(notBefore)) {
                isGranted = false;
            } else {
                advices.add(Advice.withCategory("time").addProperty("nbf", notBefore).build());
            }
        }

        String notOnOrAfter = this.policy.getConfig().get("noa");

        if (notOnOrAfter != null) {
            if (Time.currentTime() > Integer.parseInt(notOnOrAfter)) {
                isGranted = false;
            } else {
                advices.add(Advice.withCategory("time").addProperty("noa", expires).build());
            }
        }

        if (isGranted) {
            evaluation.grantWithAdvices(advices);
        }
    }
}

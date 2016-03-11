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
import org.keycloak.authz.core.policy.Evaluation;
import org.keycloak.authz.core.policy.provider.PolicyProvider;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JSPolicyProvider implements PolicyProvider {

    private final Policy policy;

    public JSPolicyProvider(Policy policy) {
        this.policy = policy;
    }

    @Override
    public void evaluate(Evaluation evaluation) {
        ScriptEngineManager manager = new ScriptEngineManager();
        ScriptEngine engine = manager.getEngineByName("nashorn");

        engine.put("$evaluation", evaluation);

        try {
            engine.eval(policy.getConfig().get("code"));
        } catch (ScriptException e) {
            e.printStackTrace();
        }
    }
}

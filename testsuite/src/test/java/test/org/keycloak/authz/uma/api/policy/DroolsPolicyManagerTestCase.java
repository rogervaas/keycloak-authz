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
package test.org.keycloak.authz.uma.api.policy;

import java.util.Collection;
import org.junit.Test;
import org.kie.api.KieServices;
import org.kie.api.runtime.KieContainer;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class DroolsPolicyManagerTestCase {

    @Test
    public void testEvaluate() {
        KieServices ks = KieServices.Factory.get();
        KieContainer container = ks.newKieContainer(ks.newReleaseId("org.keycloak", "photoz-authz-policy", "1.0-SNAPSHOT"));

        for (String moduleName : container.getKieBaseNames()) {
            Collection<String> base = container.getKieSessionNamesInKieBase(moduleName);

            for (String sessionName : base) {
                System.out.println(sessionName);
            }
        }
    }
}

package org.keycloak.authz.core.policy.io;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface PolicyEvaluation {
    void evaluate(Decision decision);
}

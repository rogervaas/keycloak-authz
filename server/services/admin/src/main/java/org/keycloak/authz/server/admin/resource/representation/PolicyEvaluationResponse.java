package org.keycloak.authz.server.admin.resource.representation;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.policy.DefaultEvaluationContext;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.policy.EvaluationResult;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluationResponse {

    private Authorization authorizationManager;
    private List<EvaluationResultRepresentation> results;
    private EvaluationResult.PolicyResult.Status status;

    public static PolicyEvaluationResponse build(RealmModel realm, DefaultEvaluationContext context, List<EvaluationResult> results, ResourceServer resourceServer, Authorization authorizationManager, KeycloakSession keycloakSession) {
        PolicyEvaluationResponse response = new PolicyEvaluationResponse();
        if (context.isGranted()) {
            response.setStatus(EvaluationResult.PolicyResult.Status.GRANTED);
        } else {
            response.setStatus(EvaluationResult.PolicyResult.Status.DENIED);
        }
        List<EvaluationResultRepresentation> resultsRep = new ArrayList<>();
        for (EvaluationResult result : results) {
            EvaluationResultRepresentation rep = new EvaluationResultRepresentation();
            rep.setStatus(result.getStatus());
            resultsRep.add(rep);
            if (result.getPermission().getResource() != null) {
                rep.setResource(Models.toRepresentation(result.getPermission().getResource(), resourceServer, authorizationManager, realm, keycloakSession));
            } else {
                ResourceRepresentation resource = new ResourceRepresentation();

                resource.setName("Any Resource with Scopes");

                rep.setResource(resource);
            }
            rep.setScopes(result.getPermission().getScopes().stream().map(Models::toRepresentation).collect(Collectors.toList()));
            List<PolicyResultRepresentation> policies = new ArrayList<>();
            for (EvaluationResult.PolicyResult policy : result.getResults()) {
                policies.add(toRepresentation(authorizationManager, policy));
            }
            rep.setPolicies(policies);
        }
        response.setResults(resultsRep);
        return response;
    }

    public static PolicyResultRepresentation toRepresentation(final Authorization authorizationManager, final EvaluationResult.PolicyResult policy) {
        PolicyResultRepresentation policyResultRep = new PolicyResultRepresentation();

        policyResultRep.setPolicy(Models.toRepresentation(policy.getPolicy(), authorizationManager));
        policyResultRep.setStatus(policy.getStatus());
        policyResultRep.setAssociatedPolicies(policy.getAssociatedPolicies().stream().map(new Function<EvaluationResult.PolicyResult, PolicyResultRepresentation>() {
            @Override
            public PolicyResultRepresentation apply(final EvaluationResult.PolicyResult result) {
                return toRepresentation(authorizationManager, result);
            }
        }).collect(Collectors.toList()));

        return policyResultRep;
    }

    public void setResults(final List<EvaluationResultRepresentation> results) {
        this.results = results;
    }

    public List<EvaluationResultRepresentation> getResults() {
        return results;
    }

    public void setStatus(final EvaluationResult.PolicyResult.Status status) {
        this.status = status;
    }

    public EvaluationResult.PolicyResult.Status getStatus() {
        return status;
    }

    public static class EvaluationResultRepresentation {

        private ResourceRepresentation resource;
        private List<ScopeRepresentation> scopes;
        private List<PolicyResultRepresentation> policies;
        private EvaluationResult.PolicyResult.Status status;

        public void setResource(final ResourceRepresentation resource) {
            this.resource = resource;
        }

        public ResourceRepresentation getResource() {
            return resource;
        }

        public void setScopes(List<ScopeRepresentation> scopes) {
            this.scopes = scopes;
        }

        public List<ScopeRepresentation> getScopes() {
            return scopes;
        }

        public void setPolicies(final List<PolicyResultRepresentation> policies) {
            this.policies = policies;
        }

        public List<PolicyResultRepresentation> getPolicies() {
            return policies;
        }

        public void setStatus(final EvaluationResult.PolicyResult.Status status) {
            this.status = status;
        }

        public EvaluationResult.PolicyResult.Status getStatus() {
            return status;
        }
    }

    public static class PolicyResultRepresentation {

        private PolicyRepresentation policy;
        private EvaluationResult.PolicyResult.Status status;
        private List<PolicyResultRepresentation> associatedPolicies;

        public PolicyRepresentation getPolicy() {
            return policy;
        }

        public void setPolicy(final PolicyRepresentation policy) {
            this.policy = policy;
        }

        public EvaluationResult.PolicyResult.Status getStatus() {
            return status;
        }

        public void setStatus(final EvaluationResult.PolicyResult.Status status) {
            this.status = status;
        }

        public List<PolicyResultRepresentation> getAssociatedPolicies() {
            return associatedPolicies;
        }

        public void setAssociatedPolicies(final List<PolicyResultRepresentation> associatedPolicies) {
            this.associatedPolicies = associatedPolicies;
        }
    }
}

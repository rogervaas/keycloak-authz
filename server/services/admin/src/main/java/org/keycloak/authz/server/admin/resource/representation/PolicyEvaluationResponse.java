package org.keycloak.authz.server.admin.resource.representation;

import org.keycloak.authz.core.Authorization;
import org.keycloak.authz.core.Decision;
import org.keycloak.authz.core.model.Resource;
import org.keycloak.authz.core.model.ResourceServer;
import org.keycloak.authz.core.policy.evaluation.Result;
import org.keycloak.authz.server.admin.resource.util.Models;
import org.keycloak.authz.server.services.common.representation.Permission;
import org.keycloak.authz.server.services.common.util.Permissions;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyEvaluationResponse {

    private List<EvaluationResultRepresentation> results;
    private boolean entitlements;
    private Decision.Effect status;

    private PolicyEvaluationResponse() {

    }

    public static PolicyEvaluationResponse build(PolicyEvaluationRequest evaluationRequest, RealmModel realm, List<Result> results, ResourceServer resourceServer, Authorization authorizationManager, KeycloakSession keycloakSession) {
        PolicyEvaluationResponse response = new PolicyEvaluationResponse();
        List<EvaluationResultRepresentation> resultsRep = new ArrayList<>();

        response.entitlements = evaluationRequest.isEntitlements();

        if (response.entitlements) {
            List<Permission> entitlements = Permissions.entitlements(results);

            if (entitlements.isEmpty()) {
                response.status = Decision.Effect.DENY;
            } else {
                for (Permission permission : entitlements) {
                    EvaluationResultRepresentation rep = new EvaluationResultRepresentation();

                    rep.setStatus(Decision.Effect.PERMIT);
                    resultsRep.add(rep);

                    Resource resource = authorizationManager.getStoreFactory().getResourceStore().findById(permission.getResourceSetId());

                    rep.setResource(Models.toRepresentation(resource, resourceServer, authorizationManager, realm, keycloakSession));
                    rep.setScopes(permission.getScopes().stream().map(ScopeRepresentation::new).collect(Collectors.toList()));
                }
            }
        } else {
            if (results.stream().anyMatch(evaluationResult -> evaluationResult.getStatus().equals(Decision.Effect.DENY))) {
                response.status = Decision.Effect.DENY;
            } else {
                response.status = Decision.Effect.PERMIT;
            }

            for (Result result : results) {
                EvaluationResultRepresentation rep = new EvaluationResultRepresentation();

                rep.setStatus(result.getStatus());
                resultsRep.add(rep);

                if (result.getPermission().getResource() != null) {
                    rep.setResource(Models.toRepresentation(result.getPermission().getResource(), resourceServer, authorizationManager, realm, keycloakSession));
                } else {
                    ResourceRepresentation resource = new ResourceRepresentation();

                    resource.setName("Any Resource with Scopes " + result.getPermission().getScopes());

                    rep.setResource(resource);
                }

                rep.setScopes(result.getPermission().getScopes().stream().map(Models::toRepresentation).collect(Collectors.toList()));

                List<PolicyResultRepresentation> policies = new ArrayList<>();

                for (Result.PolicyResult policy : result.getResults()) {
                    policies.add(toRepresentation(policy, authorizationManager));
                }

                rep.setPolicies(policies);
            }
        }

        response.results = resultsRep;

        return response;
    }

    private static PolicyResultRepresentation toRepresentation(Result.PolicyResult policy, Authorization authorizationManager) {
        PolicyResultRepresentation policyResultRep = new PolicyResultRepresentation();

        policyResultRep.setPolicy(Models.toRepresentation(policy.getPolicy(), authorizationManager));
        policyResultRep.setStatus(policy.getStatus());
        policyResultRep.setAssociatedPolicies(policy.getAssociatedPolicies().stream().map(result -> toRepresentation(result, authorizationManager)).collect(Collectors.toList()));

        return policyResultRep;
    }

    public List<EvaluationResultRepresentation> getResults() {
        return results;
    }

    public Decision.Effect getStatus() {
        return status;
    }

    public boolean isEntitlements() {
        return entitlements;
    }

    public static class EvaluationResultRepresentation {

        private ResourceRepresentation resource;
        private List<ScopeRepresentation> scopes;
        private List<PolicyResultRepresentation> policies;
        private Decision.Effect status;

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

        public void setStatus(final Decision.Effect status) {
            this.status = status;
        }

        public Decision.Effect getStatus() {
            return status;
        }
    }

    public static class PolicyResultRepresentation {

        private PolicyRepresentation policy;
        private Decision.Effect status;
        private List<PolicyResultRepresentation> associatedPolicies;

        public PolicyRepresentation getPolicy() {
            return policy;
        }

        public void setPolicy(final PolicyRepresentation policy) {
            this.policy = policy;
        }

        public Decision.Effect getStatus() {
            return status;
        }

        public void setStatus(final Decision.Effect status) {
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

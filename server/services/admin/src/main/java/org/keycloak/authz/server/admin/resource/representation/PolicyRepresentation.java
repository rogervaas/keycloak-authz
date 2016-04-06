package org.keycloak.authz.server.admin.resource.representation;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.keycloak.authz.core.model.Policy;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class PolicyRepresentation {

    private String id;
    private String name;
    private String description;
    private String type;
    private Policy.Logic logic;
    private Policy.DecisionStrategy decisionStrategy;
    private Map<String, String> config = new HashMap();
    private List<PolicyRepresentation> dependentPolicies;

    public String getId() {
        return this.id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public Policy.DecisionStrategy getDecisionStrategy() {
        return this.decisionStrategy;
    }

    public void setDecisionStrategy(Policy.DecisionStrategy decisionStrategy) {
        this.decisionStrategy = decisionStrategy;
    }

    public Policy.Logic getLogic() {
        return logic;
    }

    public void setLogic(Policy.Logic logic) {
        this.logic = logic;
    }

    public Map<String, String> getConfig() {
        return this.config;
    }

    public void setConfig(Map<String, String> config) {
        this.config = config;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @Override
    public boolean equals(final Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        final PolicyRepresentation policy = (PolicyRepresentation) o;
        return Objects.equals(getId(), policy.getId());
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId());
    }

    public void setDependentPolicies(List<PolicyRepresentation> dependentPolicies) {
        this.dependentPolicies = dependentPolicies;
    }

    public List<PolicyRepresentation> getDependentPolicies() {
        return this.dependentPolicies;
    }
}
package org.keycloak.authz.core.model;

import java.util.Map;
import java.util.Set;

/**
 * Represents an authorization policy and all the configuration associated with it.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Policy {

    /**
     * Returns the unique identifier for this instance.
     *
     * @return the unique identifier for this instance
     */
    String getId();

    /**
     * Returns the type of this policy.
     *
     * @return the type of this policy
     */
    String getType();

    /**
     * Returns the {@link DecisionStrategy} for this policy.
     *
     * @return the decision strategy defined for this policy
     */
    DecisionStrategy getDecisionStrategy();

    /**
     * Sets the {DecisionStrategy} for this policy.
     *
     * @return the decision strategy for this policy
     */
    void setDecisionStrategy(DecisionStrategy decisionStrategy);

    /**
     * Returns the {@link Logic} for this policy.
     *
     * @return the decision strategy defined for this policy
     */
    Logic getLogic();

    /**
     * Sets the {Logic} for this policy.
     *
     * @return the decision strategy for this policy
     */
    void setLogic(Logic logic);

    /**
     * Returns a {@link Map} holding string-based key/value pairs representing any additional configuration for this policy.
     *
     * @return a map with any additional configuration defined for this policy.
     */
    Map<String, String> getConfig();

    /**
     * Sets a {@link Map} with string-based key/value pairs representing any additional configuration for this policy.
     *
     * @return a map with any additional configuration for this policy.
     */
    void setConfig(Map<String, String> config);

    /**
     * Returns the name of this policy.
     *
     * @return the name of this policy
     */
    String getName();

    /**
     * Sets an unique name to this policy.
     *
     * @param name an unique name
     */
    void setName(String name);

    /**
     * Returns the description of this policy.
     *
     * @return a description or null of there is no description
     */
    String getDescription();

    /**
     * Sets the description for this policy.
     *
     * @param description a description
     */
    void setDescription(String description);

    /**
     * Returns the {@link ResourceServer} where this policy belongs to.
     *
     * @return a resource server
     */
    ResourceServer getResourceServer();

    /**
     * Returns the {@link Policy} instances associated with this policy and used to evaluate authorization decisions when
     * this policy applies.
     *
     * @return the associated policies or an empty set if no policy is associated with this policy
     */
    Set<Policy> getAssociatedPolicies();

    /**
     * Returns the {@link Resource} instances where this policy applies.
     *
     * @return a set with all resource instances where this policy applies. Or an empty set if there is no resource associated with this policy
     */
    Set<Resource> getResources();

    /**
     * Returns the {@link Scope} instances where this policy applies.
     *
     * @return a set with all scope instances where this policy applies. Or an empty set if there is no scope associated with this policy
     */
    Set<Scope> getScopes();

    /**
     * Adds a {@link Scope} to this policy.
     *
     * @param scope the scope
     */
    void addScope(Scope scope);

    /**
     * Removes a {@link Scope} from this policy.
     *
     * @param scope the scope
     */
    void removeScope(Scope scope);

    /**
     * Adds a {@link Resource} to this policy.
     *
     * @param scope the resource
     */
    void addResource(Resource resource);

    /**
     * Removes a {@link Resource} from this policy.
     *
     * @param scope the resource
     */
    void removeResource(Resource resource);

    /**
     * Associates another {@link Policy} with this policy.
     *
     * @param scope the policy
     */
    void addAssociatedPolicy(Policy policy);

    /**
     * Removes an associated {@link Policy} from this policy.
     *
     * @param scope the policy
     */
    void removeAssociatedPolicy(Policy policy);

    /**
     * The decision strategy dictates how the policies associated with a given policy are evaluated and how a final decision
     * is obtained.
     */
    enum DecisionStrategy {
        /**
         * Defines that at least one policy must evaluate to a positive decision in order to the overall decision be also positive.
         */
        AFFIRMATIVE,

        /**
         * Defines that all policies must evaluate to a positive decision in order to the overall decision be also positive.
         */
        UNANIMOUS,

        /**
         * Defines that the number of positive decisions must be greater than the number of negative decisions. If the number of positive and negative is the same,
         * the final decision will be negative.
         */
        CONSENSUS
    }

    /**
     * The decision strategy dictates how the policies associated with a given policy are evaluated and how a final decision
     * is obtained.
     */
    enum Logic {
        /**
         * Defines that this policy follows a positive logic. In other words, the final decision is the policy outcome.
         */
        POSITIVE,

        /**
         * Defines that this policy uses a logical negation. In other words, the final decision would be a negative of the policy outcome.
         */
        NEGATIVE,
    }
}

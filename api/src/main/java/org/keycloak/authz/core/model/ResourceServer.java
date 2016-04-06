package org.keycloak.authz.core.model;

/**
 * Represents a resource server, whose resources are managed and protected. A resource server is basically an existing
 * client application in Keycloak that will also act as a resource server.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface ResourceServer {

    /**
     * Returns the unique identifier for this instance.
     *
     * @return the unique identifier for this instance
     */
    String getId();

    /**
     * Returns the identifier of the client application (which already exists in Keycloak) that is also acting as a resource
     * server.
     *
     * @return the identifier of the client application associated with this instance.
     */
    String getClientId();

    /**
     * Indicates if the resource server is allowed to manage its own resources remotely using the Protection API.
     *
     * {@code true} if the resource server is allowed to managed them remotely
     */
    boolean isAllowRemoteResourceManagement();

    /**
     * Indicates if the resource server is allowed to manage its own resources remotely using the Protection API.
     *
     * @param allowRemoteResourceManagement {@code true} if the resource server is allowed to managed them remotely
     */
    void setAllowRemoteResourceManagement(boolean allowRemoteResourceManagement);

    /**
     * Indicates if the resource server is allowed to manage its own authorization policies remotely using the Protection API.
     *
     * @return {@code true} if the resource server is allowed to managed them remotely
     */
    boolean isAllowEntitlements();

    /**
     * Indicates if the resource server is allowed to manage its own authorization policies remotely using the Protection API.
     *
     * @param allowRemotePolicyManagement {@code true} if the resource server is allowed to managed them remotely
     */
    void setAllowEntitlements(boolean allowRemotePolicyManagement);

    /**
     * Returns the {@code PolicyEnforcementMode} configured for this instance.
     *
     * @return the {@code PolicyEnforcementMode} configured for this instance.
     */
    PolicyEnforcementMode getPolicyEnforcementMode();

    /**
     * Defines a {@code PolicyEnforcementMode} for this instance.
     *
     * @param enforcementMode one of the available options in {@code PolicyEnforcementMode}
     */
    void setPolicyEnforcementMode(PolicyEnforcementMode enforcementMode);

    /**
     * The policy enforcement mode dictates how authorization requests are handled by the server.
     */
    enum PolicyEnforcementMode {
        /**
         * Requests are denied by default even when there is no policy associated with a given resource.
         */
        ENFORCING,

        /**
         * Requests are allowed even when there is no policy associated with a given resource.
         */
        PERMISSIVE,

        /**
         * Completely disables the evaluation of policies and allow access to any resource.
         */
        DISABLED
    }
}

package org.keycloak.authz.policy.enforcer.servlet;

import org.keycloak.authz.policy.enforcer.servlet.Configuration.PathConfig;

import java.util.List;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
class PathMatcher {

    private static final String ANY_RESOURCE_PATTERN = "/*";

    PathConfig matches(final String requestedUri, List<PathConfig> paths) {
        PathConfig actualConfig = null;

        for (PathConfig entry : paths) {
            String protectedUri = entry.getPath();
            String selectedUri = null;

            if (protectedUri.equals(ANY_RESOURCE_PATTERN) && actualConfig == null) {
                selectedUri = protectedUri;
            }

            int suffixIndex = protectedUri.indexOf(ANY_RESOURCE_PATTERN + ".");

            if (suffixIndex != -1) {
                String protectedSuffix = protectedUri.substring(suffixIndex + ANY_RESOURCE_PATTERN.length());

                if (requestedUri.endsWith(protectedSuffix)) {
                    selectedUri = protectedUri;
                }
            }

            if (protectedUri.equals(requestedUri)) {
                selectedUri = protectedUri;
            }

            if (protectedUri.endsWith(ANY_RESOURCE_PATTERN)) {
                String formattedPattern = removeWildCardsFromUri(protectedUri);

                if (!formattedPattern.equals("/") && requestedUri.startsWith(formattedPattern)) {
                    selectedUri = protectedUri;
                }

                if (!formattedPattern.equals("/") && formattedPattern.endsWith("/") && formattedPattern.substring(0, formattedPattern.length() - 1).equals(requestedUri)) {
                    selectedUri = protectedUri;
                }
            }

            int startRegex = protectedUri.indexOf('{');

            if (startRegex != -1) {
                String prefix = protectedUri.substring(0, startRegex);

                if (requestedUri.startsWith(prefix)) {
                    selectedUri = protectedUri;
                }
            }

            if (selectedUri != null) {
                selectedUri = protectedUri;
            }

            if (selectedUri != null) {
                if (actualConfig == null) {
                    actualConfig = entry;
                } else {
                    if (actualConfig.equals(ANY_RESOURCE_PATTERN)) {
                        actualConfig = entry;
                    }

                    if (protectedUri.startsWith(removeWildCardsFromUri(actualConfig.getPath()))) {
                        actualConfig = entry;
                    }
                }
            }
        }

        return actualConfig;
    }

    private String removeWildCardsFromUri(String protectedUri) {
        return protectedUri.replaceAll("/[*]", "/");
    }
}

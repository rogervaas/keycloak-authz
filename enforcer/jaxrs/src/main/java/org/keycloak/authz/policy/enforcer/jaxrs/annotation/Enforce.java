package org.keycloak.authz.policy.enforcer.jaxrs.annotation;


import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
@Target({ElementType.METHOD, ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Enforce {
    String uri() default "";
    String[] scopes();
}

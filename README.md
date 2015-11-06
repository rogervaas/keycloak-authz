# Keycloak Authorization Server

This a temporary repository holding an Authorization Server based on [Keycloak](https://github.com/keycloak/keycloak).

It is under heavy development and should be used only for evaluation or testing purposes. If you need to get it running, please reach me on IRC, #keycloak on Freenode.

More documentation about concepts, installation, configuration, how to use it and examples will be added as soon as some things are defined.

## Overview

This projects leverage Keycloak Authorization capabilities in order to support fine-grained permissions and policies with a mix
and match of different access control mechanisms such as:

* Role-based

* User-based

* Context-based

* Attribute-based

* Rule-based
    * JBoss Drools
    * XACML (planned)

The whole concept is based on a Keycloak client application acting as a resource server, which resources and their respective scopes
are protected and ruled by a set of authorization policies. Any client application serving resources to its users can be considered as a resource server. 
Where these resources are part of the assets of an application and organization.

The authorization server is based on three main APIs:

* Protection API
* Authorization API
* Entitlements API

Based on some common authorization patterns, this authorization server provides the following:

* Policy Administration Point (PAP)
    * Provides a set of UIs, based on the Keycloak Administration Console, to manage resource servers, resources, scopes and policies.
    * Part of this also accomplished remotely through the use of the Protection API 
     
* Policy Decision Point (PDP)
    * Provides a distributable policy decision point, to where authorization requests are sent and policies are evaluated.
    * Part of this also accomplished remotely through the use of the Authorization API
    
* Policy Enforcement point (PEP)
    * Provides implementations for different technologies and platforms to actually enforce authorization policies on the resource server side.
      
Instead of doing authorization by your own, this project provides a centralized but still distributable server to govern the protected resources
and their respective policies within an application or organization using some well-known authorization patterns and standards such as OAuth2 and User-Managed Access (UMA).

When talking about Web API Security, an authorization server plays an important role. Today we need to consider a very 
heteregenous environment, where users are distributed across different regions, with different local policies, using different devices and
with a high demand for information sharing.

Being based on both OAuth2 and UMA concepts, this project can be used as great tool to:

* Control your protected resources and the actions that can be performed on them
* Centralize Policy Management
* Support a centralized and RESTful-based Athorization Services for different platforms and environments    
* Audit and analyse authorization requests and decision results
* Avoid replicate code across projects or redeploy your applications when your policies need to change
* Provide a better and more secure way to your users share information


### The Protection API

The **Protection API** provides ways for resource servers to remotely register the resources they want to protect, as well manage policies
and permissions for these resources.

### The Authorization API

The **Authorization API** provides ways for any client application to ask for authorization for a given set of resources and/or any scopes. When
asking for authorization, all policies associated with the resources and/or scopes being requested will be evaluated, as a result the server
will return a specific token that can finally be used to access a protected resource on a resource server.

### The Entitlements API

The **Entitlements API** provides ways for any client application to ask for all the permissions for a given user, based on the policies
associated with each resource. In other words, it provides for clients what an user is entitled to do in the scope of a given resource server, which resources
and scopes can be accessed. Like the Authorization API, the result is also a specific token containing all the entitlements for an user, which can be used
in turn to access the protected resources on the resource server.

## Build

TODO: need to describe how to build the modified version of Keycloak
        
## Run and Deploy Examples

TODO: make easier to run the authorization server and run examples

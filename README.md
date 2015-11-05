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

## Protection API

The **Protection API** provides ways for resource servers to remotely register the resources they want to protect, as well manage policies
and permissions for these resources.

## Authorization API

The **Authorization API** provides ways for any client application to ask for authorization for a given set of resources and/or any scopes. When
asking for authorization, all policies associated with the resources and/or scopes being requested will be evaluated, as a result the server
will return a specific token that can finally be used to access a protected resource on a resource server.

## Entitlements API

The **Entitlements API** provides ways for any client application to ask for all the permissions for a given user, based on the policies
associated with each resource. In other words, it provides for clients what an user is entitled to do in the scope of a given resource server, which resources
and scopes can be accessed. Like the Authorization API, the result is also a specific token containing all the entitlements for an user, which can be used
in turn to access the protected resources on the resource server.


## Steps to configure a client application as a resource server

* Create a client application
* Enable "Service Accounts Enabled"
* Assign "uma_protection" role to client in "Service Account Roles"

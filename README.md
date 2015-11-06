# Keycloak Authorization Server

This a temporary repository holding an Authorization Server based on [Keycloak](https://github.com/keycloak/keycloak).

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

The whole concept is based on a Keycloak client application acting as a resource server, which resources and its respective scopes
are protected and ruled by a set of authorization policies. Any client application serving resources to its users can be considered a resource server,  
where these resources are part of the assets of an application and the organization.

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
heterogeneous environment, where users are distributed across different regions, with different local policies, using different devices and
with a high demand for information sharing.

Being based on both OAuth2 and UMA concepts, this project can be used as great tool to:

* Control your protected resources and the actions that can be performed on them
* Centralize Policy Management
* Support a centralized and RESTful-based Athorization Services for different platforms and environments    
* Audit and analyse authorization requests and decision results
* Avoid replicate code across projects or redeploy your applications when your policies need to change
* Provide a better and more secure way to your users share information
* Obligations and Advices
* Alerts and Notifications
* Authorization and Resource Sharing Flows

Some of these features are planned or are being developed. Feel free to contribute :)


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

Before building this project you must clone and build a Keycloak branch, which contains some changes to get the AuthZ Server
properly integrated with Keycloak SPIs. This is a temporary step and we will get these changes merged very soon. That said,
use the following commands to clone and build the modified Keycloak version:

    git clone git@github.com:pedroigor/keycloak.git
    cd keycloak
    git checkout -b keycloak-authz-modified    
    mvn -DskipTests clean install
    
Now you can clone and this project using the following command:

    git clone git@github.com:pedroigor/keycloak-authz.git
    cd keycloak-authz
    mvn -DskipTests -Pdistribution clean install
        
## Install and Start the Authz Server (Demo Distribution) 

Once the project was built, you can obtain a distribution that can be used to start the AuthZ Server and run some example applications.

The demo distribution is located at:

    distribution/demo/target/keycloak-authz-demo-dist-1.0-SNAPSHOT.zip
    
Now, extract that file and you'll have a full Keycloak Server with the AuthZ Server extension installed.

    unzip -d /to/this/directory distribution/demo/target/keycloak-authz-demo-dist-1.0-SNAPSHOT.zip
     
Change ``/to/this/directory`` to the directory where you want to install the AuthZ Server.

You should be able now to enter into the  directory where the AuthZ Server is installed and run the server.
 
    cd /to/this/directory
    cd bin
    ./standalone.sh
    
If everything is fine, you should now be able to access the server at:

    http://localhost:8080/auth

## About the Example Application

For now, there is a single example application based on HTML5+AngularJS+JAX-RS that will introduce you to some of the main
concepts around the AuthZ Server.

The example application is located at:
 
    cd examples/photoz
    
Basically, it is a project with three modules:
 
* **photoz-restful-api**, providing a simple RESTFul API based on JAX-RS and acting as a regular **client application**.
* **photoz-html5-client**, providing a HTML5+AngularJS client that will consume the RESTful API and acting as a **resource server**.
* **photoz-authz-policy**, providing a simple project with some rule-based policies using JBoss Drools.

For this application, users can be regular users or administrators. Regular users can create/view/delete only their albums 
and administrators can view the albums for all users.

For the AuthZ Server, albums are resources that must be protected based on a set of rules that may define who and how can access them.
In turn, resources belong to a specific resource server, in this case to the *photoz-restful-api*.

The resources are also associated with a set of scopes that define a specific access context such as a operation that can be performed on them.

In this case, albums have three main scopes:

* urn:photoz.com/dev/scopes/album/create
* urn:photoz.com/dev/scopes/album/view
* urn:photoz.com/dev/scopes/album/delete

The authorization requirements for this example application are based on the following premises:

* By default, any regular user can perform any operation on their albums resources. Here we are considering policies based on the resource type.

    * For instance, Alice can create, view and delete her albums. In this case, the policy that applies to the *create* scope is defined on the resource type level. 

* Only the owner of a album can delete it. Here we are considering policies based on a resource instance, in other words, a album which is owned by an user.

    * For instance, only Alice can delete her album. Even administrators can not delete users albums. In this case, the policy that applies to the *delete* scope is enforced on resource instances.

* Only administrators can access the Administrative API (which basically provides ways to query albums for all users)

That said, this application will show you how to use the AuthZ Server to define policies involving:

* Role-based Access Control
* Attribute-based Access Control
* Rule-based policies using JBoss Drools

It also provides some background on how you can actually protect your JAX-RS endpoints using a *enforcer*.

### Create the Example Realm and a Resource Server

Considering that your AuthZ Server is up and running, log in to the Keycloak Administration Console.

Once you are there, click on ``Realm Settings`` on the left side menu and then click on the ``Themes`` tab. In the themes tab,
choose the ``keycloak-authz`` as the theme for the ``Admin Console Theme``. 

Refresh your browser and check if there is a ``Resource Servers`` option on the left side menu.

Now, create a new realm based on the following configuration file:

    examples/photoz/photoz-realm.json
    
This will import a pre-configured realm with everything you need to run this example. For more details about how to import a realm 
into Keycloak, check the reference documentation.

After importing that file, you'll have a new realm called ``photoz``. 

Back to the command-line, build the example application. This step is necessary given that we're using policies based on
JBoss Drools, which require ``photoz-authz-policy`` to be available in your local maven repository.

    cd examples/photoz
    mvn clean install 

Now, let's import another configuration using the Administration Console in order to configure the ``photoz-restful-api`` as a resource server with all resources, scopes and policies.

Click on ``Resource Servers`` on the left side menu. Click on the ``Create`` button on the top of the resource server table. This will
open the page that allows you to create a new resource server.

Click on the ``Select file`` button, which means you want to import a resource server configuration. Now select the file that is located at:

    examples/photoz/photoz-restful-api/photoz-restful-api-authz-config.json
    
Now click ``Upload`` and a new resource server will be created based on the ``photoz-restful-api`` client application.

### Deploy and Run the Example Applications

To deploy the example applications, follow these steps:

    cd examples/photoz/photoz-html5-client
    mvn wildfly:deploy
    
And then:

    cd examples/photoz/photoz-restful-api
    mvn wildfly:deploy
   
Now, try to access the client application using the following URL:

    http://localhost:8080/photoz-html5-client

If everything is correct, you will be redirect to Keycloak login page. You can login to the application with the following credentials:

* username: jdoe / password: jdoe
* username: alice / password: alice
* username: admin / password: admin

## Considerations

Consider using this project for evaluation purposes only, right now it is under heavy development and is not prepared to go for
production.

More details about how the authorization happens, protocols and constraints will be added soon. In a nutshell, we're using a lot
of stuff from UMA and still evaluating which parts require customizations.

More features and documentation are coming, if you have any suggestion or any issue with this initial documentation, please
file a  GitHub Issue.
# DuoUniversalKeycloakAuthenticator
Authenticator for [Keycloak](https://github.com/keycloak/keycloak) that uses Duo's [Java Universal Prompt SDK](https://github.com/duosecurity/duo_universal_java) to challenge the user for Duo MFA as part of a Keycloak login flow.

This has been tested against Keycloak 24.0.2 (Quarkus) and Java 18+. It may work against other versions of Keycloak and Java as well but is untested.

## How to use
### Install the authenticator extension
1. Build or download the pre-built "DuoUniversalKeycloakAuthenticator-jar-with-dependencies.jar" JAR file.
2. Copy this JAR file to the deployments folder on the Keycloak server. The exact location of this folder may be different depending on the installation configuration. For example, in the Quarkus (Keycloak 17.0+ default) docker image, the path is `/opt/keycloak/providers`. In the legacy Docker image using WildFly, the path is `/opt/jboss/keycloak/standalone/deployments`.
3. Restart the Keycloak application server.

### Configure the authenticator
1. First, create a new application in the Duo Admin Panel. The application should be of the type "Web SDK".
  ![Creating new application in Duo Portal!](https://raw.githubusercontent.com/instipod/DuoUniversalKeycloakAuthenticator/master/documentation/duo-create-1.png "Step 1 in Duo Admin")
2. Add the "Duo Universal MFA" authenticator to a spot in the Keycloak authentication flow.
  ![Creating new authenticator in Keycloak!](https://raw.githubusercontent.com/instipod/DuoUniversalKeycloakAuthenticator/master/documentation/keycloak-create-1.png "Step 1 in Keycloak Admin")
3. Set the authenticator to REQUIRED, and then click Config on the authenticator to change the settings.
  ![Configure the authenticator in Keycloak!](https://raw.githubusercontent.com/instipod/DuoUniversalKeycloakAuthenticator/master/documentation/keycloak-create-2.png "Step 2 in Keycloak Admin")
4. Copy the Integration Key (Client ID), Secret Key, and API Hostname from the newly created application in the Duo Admin Panel and paste them into the boxes under Authenticator Config in Keycloak.
  ![View new application in Duo Portal!](https://raw.githubusercontent.com/instipod/DuoUniversalKeycloakAuthenticator/master/documentation/duo-create-2.png "Step 2 in Duo Admin")
  ![Setting configuration options in Keycloak!](https://raw.githubusercontent.com/instipod/DuoUniversalKeycloakAuthenticator/master/documentation/keycloak-create-3.png "Step 3 in Keycloak Admin")
5. You may now configure policies in Duo and they will be applied in your Keycloak flow.
6. (Optional) If you want to use different Duo Applications for different Keycloak clients, you can specify them in the Client Overrides option.
  
    For each different client, add a new config line next to Client Overrides in the format of `{Keycloak Client ID},{Duo Client ID},{Duo Client Secret},{Duo API Hostname}`.
  
    You can retrieve the Keycloak Client ID by looking at the end of the admin URL when editing a client. For example:  `http://localhost:8080/auth/admin/master/console/#/realms/master/clients/f181f907-ce3f-49fd-97c5-eb3eafe275a7` is client ID `f181f907-ce3f-49fd-97c5-eb3eafe275a7`.

## Building on your computer
You should be able to build and package this project using Maven. The maven package command will compile the source code and build the JAR files for you. You will need to use the output JAR that includes dependencies as otherwise Keycloak won't be able to find the embedded libraries.

`mvn clean package`

## Building using Docker
You should be able to build and package this project using Docker. The docker run command will compile the source code and build the JAR files for you. You will need to use the output JAR that includes dependencies as otherwise Keycloak won't be able to find the embedded libraries.

`docker run --rm -it -v $(pwd):/project_src -w /project_src maven:3.8-eclipse-temurin-18 mvn clean package`

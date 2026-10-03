# DuoUniversalKeycloakAuthenticator
Authenticator for [Keycloak](https://github.com/keycloak/keycloak) that uses Duo's [Java Universal Prompt SDK](https://github.com/duosecurity/duo_universal_java) to challenge the user for Duo MFA as part of a Keycloak login flow.

This has been tested against Keycloak 26.8.0 using the official container image. It may work against other versions of Keycloak and Java as well but is untested.

## How to use
### Install the authenticator extension
1. Build or download the pre-built "DuoUniversalKeycloakAuthenticator-jar-with-dependencies.jar" JAR file.
2. Copy this JAR file to the deployments folder on the Keycloak server. The exact location of this folder may be different depending on the installation configuration. For example, in the Quarkus (Keycloak 17.0+ default) docker image, the path is `/opt/keycloak/providers`. In the legacy Docker image using WildFly, the path is `/opt/jboss/keycloak/standalone/deployments`.
3. Restart the Keycloak application server.

#### Deploying on Kubernetes (official container image)

When you run the official Keycloak container image on Kubernetes, you usually don't want to bake a custom image just to add a provider JAR. Instead, you can use an init container to download the JAR into an `emptyDir` volume that is shared with the Keycloak container at `/opt/keycloak/providers`. No custom image and no persistent volume are required.

The snippet below downloads the JAR from the GitHub release and verifies its SHA-256 checksum before Keycloak starts. Replace `VERSION` and the checksum with the release you want to pin to (the SHA-256 of each asset is shown on the [releases page](https://github.com/instipod/DuoUniversalKeycloakAuthenticator/releases), or run `sha256sum` on the downloaded JAR).

```yaml
spec:
  template:
    spec:
      initContainers:
        - name: download-duo-plugin
          image: busybox:1.37
          command:
            - /bin/sh
            - -c
            - |
              VERSION="1.1.1"
              JAR="duouniversalkeycloakauthenticator-${VERSION}-jar-with-dependencies.jar"
              URL="https://github.com/instipod/DuoUniversalKeycloakAuthenticator/releases/download/${VERSION}/${JAR}"
              EXPECTED_SHA256="ea540783229a89986c15da59bb73bb736b16941b09eb0d5dfdf8f284fb06ab07"

              wget -q -O "/providers/${JAR}" "$URL"
              ACTUAL_SHA256=$(sha256sum "/providers/${JAR}" | awk '{print $1}')
              if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
                echo "SHA256 mismatch! expected $EXPECTED_SHA256, got $ACTUAL_SHA256"
                exit 1
              fi
          volumeMounts:
            - name: duo-provider
              mountPath: /providers
      containers:
        - name: keycloak
          image: quay.io/keycloak/keycloak:26.0
          # ... your usual args/env ...
          volumeMounts:
            - name: duo-provider
              mountPath: /opt/keycloak/providers
      volumes:
        - name: duo-provider
          emptyDir: {}
```

Notes:

- The authenticator provider id (useful for declarative/automated configuration) is `duo-universal`.
- With `start --optimized=false` Keycloak picks the provider up at startup with no separate build step. If you run an optimized image (`kc.sh build`), make sure the JAR is present at build time instead.

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

### Protecting federated (SSO / identity provider) logins

The steps above add Duo to the **browser flow**, which covers users who sign in with a username and password directly against Keycloak. However, when a user authenticates through an external identity provider (for example Google, an OIDC/SAML IdP, or social login), Keycloak runs the IdP's **Post Login Flow** instead of the password part of the browser flow. If Duo is only present in the browser flow, those federated logins are **not** challenged for Duo and effectively bypass MFA.

To make sure every login is challenged — including brokered/SSO logins — add Duo to a Post Login Flow and bind it to your identity provider(s):

1. In the Keycloak admin console, go to **Authentication → Flows** and create a new flow (e.g. "Post Broker Login - Duo MFA").
2. Add the **Duo Universal MFA** authenticator to that flow and set it to **REQUIRED**, then set its config (Integration Key / Secret Key / API Hostname) just like in the browser flow.
3. Go to **Identity Providers**, open the provider you want to protect, and under its advanced settings set **Post Login Flow** to the flow you just created.

After this, both direct password logins and federated/SSO logins go through Duo.

## Building on your computer
You should be able to build and package this project using Maven. The maven package command will compile the source code and build the JAR files for you. You will need to use the output JAR that includes dependencies as otherwise Keycloak won't be able to find the embedded libraries.

`mvn clean package`

## Building using Docker
You should be able to build and package this project using Docker. The docker run command will compile the source code and build the JAR files for you. You will need to use the output JAR that includes dependencies as otherwise Keycloak won't be able to find the embedded libraries.

`docker run --rm -it -v $(pwd):/project_src -w /project_src maven:3-eclipse-temurin-18 mvn clean package`

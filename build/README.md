### Build container

From root of repo:

```
docker build -t duo-universal-keycloak-auth-build:latest build/
```

### Build Jar

From root of repo:

```
docker run --rm -it -v $(pwd):/build -w /build \
-e JAVA_HOME=/usr/lib/jvm/java-11-openjdk \
duo-universal-keycloak-auth-build:latest  mvn clean package
```

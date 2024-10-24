package com.instipod.duouniversal;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Collections;
import java.util.List;

public class DuoUniversalAuthenticatorFactory implements org.keycloak.authentication.AuthenticatorFactory {
    public static final String PROVIDER_ID = "duo-universal";

    protected static final String DUO_API_HOSTNAME = "duoApiHostname";
    protected static final String DUO_INTEGRATION_KEY = "duoIntegrationKey";
    protected static final String DUO_SECRET_KEY = "duoSecretKey";
    protected static final String DUO_GROUPS = "duoGroups";
    protected static final String DUO_FAIL_SAFE = "duoFailSafe";
    protected static final String DUO_CUSTOM_CLIENT_IDS = "duoClientIds";
    protected static final String DUO_USE_IMPERSONATOR = "duoUseImpersonator";
    protected static final String DUO_USERNAME_FORMATTER_REGEX_MATCH = "duoUsernameFormatterRegexMatch";
    protected static final String DUO_USERNAME_FORMATTER_REGEX_REPLACE = "duoUsernameFormatterRegexReplace";
    protected static final String DUO_USERNAME_CUSTOM_ATTRIBUTE = "duoUsernameCustomAttribute";
    private final static List<ProviderConfigProperty> commonConfig;
    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.ALTERNATIVE,
            AuthenticationExecutionModel.Requirement.DISABLED
    };

    static {
        commonConfig = Collections.unmodifiableList(ProviderConfigurationBuilder.create()
                .property().name(DUO_API_HOSTNAME).label("Duo API Hostname").helpText("Domain name provided by Duo to contact").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_INTEGRATION_KEY).label("Duo Integration Key").helpText("Obtained from admin console, also called Client ID").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_SECRET_KEY).label("Duo Secret Key").helpText("Obtained from admin console, also called Client secret").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_GROUPS).label("Duo Groups").helpText("Comma separated list of groups that require Duo (optional)").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_FAIL_SAFE).label("Fail Safe").helpText("With this enabled, users will be able to login if Duo is not reachable").type(ProviderConfigProperty.BOOLEAN_TYPE).add()
                .property().name(DUO_USE_IMPERSONATOR).label("Use Impersonator").helpText("With this enabled, the Duo transaction will be performed using the impersonator's username if one exists").type(ProviderConfigProperty.BOOLEAN_TYPE).add()
                .property().name(DUO_CUSTOM_CLIENT_IDS).label("Client Overrides").helpText("Comma separated list of client-specific Duo key overrides (keycloak client id, duo client id, duo secret, (optional) API hostname)").type(ProviderConfigProperty.MULTIVALUED_STRING_TYPE).add()
                .property().name(DUO_USERNAME_FORMATTER_REGEX_MATCH).label("Username Formatter regex-match").helpText("Regex to match with to format the username").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_USERNAME_FORMATTER_REGEX_REPLACE).label("Username Formatter regex-replace").helpText("Regex to replace with (supports named groups)").type(ProviderConfigProperty.STRING_TYPE).add()
                .property().name(DUO_USERNAME_CUSTOM_ATTRIBUTE).label("Username custom attribute").helpText("Loads the Username from a custom attribute when available").type(ProviderConfigProperty.USER_PROFILE_ATTRIBUTE_LIST_TYPE).add()
                .build()
        );
    }

    @Override
    public String getDisplayType() {
        return "Duo Universal MFA";
    }

    @Override
    public String getReferenceCategory() {
        return "MFA";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Uses the Duo Universal Prompt webservice to provide 2FA services.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return commonConfig;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return DuoUniversalAuthenticator.SINGLETON;
    }

    @Override
    public void init(Config.Scope scope) {
        // noop
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
        // noop
    }

    @Override
    public void close() {
        // noop
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}

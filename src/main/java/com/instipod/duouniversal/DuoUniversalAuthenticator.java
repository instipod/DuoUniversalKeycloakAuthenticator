package com.instipod.duouniversal;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.Token;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.*;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.managers.AuthenticationManager;

import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class DuoUniversalAuthenticator implements Authenticator {
    public static final DuoUniversalAuthenticator SINGLETON = new DuoUniversalAuthenticator();
    private final static Logger logger = Logger.getLogger(DuoUniversalAuthenticator.class);

    private String getRedirectUrl(AuthenticationFlowContext context) {
        return getRedirectUrl(context, false);
    }

    private String getRedirectUrl(AuthenticationFlowContext context, Boolean forceToken) {
        if (context.getExecution().isAlternative()) {
            // We only need to shim in an alternative case, as the user may be able to "try another way"
            return getRedirectUrlShim(context, forceToken);
        } else {
            return getRedirectUrlRefresh(context);
        }
    }

    private String getRedirectUrlRefresh(AuthenticationFlowContext context) {
        return context.getRefreshUrl(false).toString();
    }

    private String getRedirectUrlShim(AuthenticationFlowContext context, Boolean forceToken) {
        MultivaluedMap<String, String> queryParams = context.getHttpRequest().getUri().getQueryParameters();
        String sessionCode;
        if (queryParams.containsKey("duo_code") && queryParams.containsKey("session_code") && !forceToken) {
            // Duo requires the same session_code as the first redirect in order to retrieve the token
            sessionCode = queryParams.getFirst("session_code");
        } else {
            sessionCode = context.generateAccessCode();
        }

        String baseUrl = context.getHttpRequest().getUri().getBaseUri().toString();
        baseUrl += "realms/" + context.getRealm().getName() + "/duo-universal/callback";
        baseUrl += "?kc_client_id=" + context.getAuthenticationSession().getClient().getClientId();
        baseUrl += "&kc_execution=" + context.getExecution().getId();
        baseUrl += "&kc_tab_id=" + context.getAuthenticationSession().getTabId();
        baseUrl += "&kc_session_code=" + sessionCode;
        return baseUrl;
    }

    private Client initDuoClient(AuthenticationFlowContext context, String redirectUrl) throws DuoException {
        AuthenticatorConfigModel authConfig = context.getAuthenticatorConfig();

        // default values
        String clientId = authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_INTEGRATION_KEY);
        String secret = authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_SECRET_KEY);
        String hostname = authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_API_HOSTNAME);

        String overrides = authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_CUSTOM_CLIENT_IDS);
        if (overrides != null && !overrides.equalsIgnoreCase("")) {
            // multivalue string seperator is ##
            String[] overridesSplit = overrides.split("##");
            for (String override : overridesSplit) {
                String[] parts = override.split(",");
                if (parts.length == 3 || parts.length == 4) {
                    String duoHostname;
                    if (parts.length == 3) {
                        duoHostname = hostname;
                    } else {
                        duoHostname = parts[3];
                    }
                    // valid entries have 3 or 4 parts: keycloak client id, duo id, duo secret, (optional) api hostname
                    String keycloakClient = parts[0];
                    String duoId = parts[1];
                    String duoSecret = parts[2];

                    if (keycloakClient.equalsIgnoreCase(context.getAuthenticationSession().getClient().getId())) {
                        // found a specific client override
                        clientId = duoId;
                        secret = duoSecret;
                        hostname = duoHostname;
                    }
                }
            }
        }

        return new Client.Builder(clientId, secret, hostname, redirectUrl).build();
    }

    private String getImpersonatorId(AuthenticationFlowContext flowContext) {
        AuthenticationManager.AuthResult authResult = AuthenticationManager.authenticateIdentityCookie(
                flowContext.getSession(), flowContext.getRealm(), true);
        if (authResult == null) {
            return null;
        }

        UserSessionModel userSession = authResult.getSession();
        Map<String, String> userSessionNotes = userSession.getNotes();
        // Check if we are impersonating a user, otherwise null
        return userSessionNotes.getOrDefault(ImpersonationSessionNote.IMPERSONATOR_ID.toString(), null);
    }

    private UserModel getImpersonatorOrUser(AuthenticationFlowContext flowContext) {
        String impersonatorId = this.getImpersonatorId(flowContext);
        UserModel baseUser = flowContext.getUser();

        if (impersonatorId == null) {
            return baseUser;
        } else {
            UserModel impersonatorUser = flowContext.getSession().users().getUserById(flowContext.getRealm(), impersonatorId);
            if (impersonatorUser != null) {
                return impersonatorUser;
            } else {
                return baseUser;
            }
        }
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticatorConfigModel authConfig = authenticationFlowContext.getAuthenticatorConfig();

        Map<String, String> authConfigMap;
        try {
            if (authConfig == null) {
                throw new NullPointerException();
            }
            authConfigMap = authConfig.getConfig();
        } catch (NullPointerException authConfigMapNull) {
            logger.error("Duo Authenticator is not configured!  All authentications will fail.");
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }

        if (authConfigMap.getOrDefault(DuoUniversalAuthenticatorFactory.DUO_API_HOSTNAME, "none").equalsIgnoreCase("none")) {
            // authenticator not configured
            logger.error("Duo Authenticator is missing API hostname configuration!  All authentications will fail.");
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        if (authConfigMap.getOrDefault(DuoUniversalAuthenticatorFactory.DUO_INTEGRATION_KEY, "none").equalsIgnoreCase("none")) {
            // authenticator not configured
            logger.error("Duo Authenticator is missing Integration Key configuration!  All authentications will fail.");
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        if (authConfigMap.getOrDefault(DuoUniversalAuthenticatorFactory.DUO_SECRET_KEY, "none").equalsIgnoreCase("none")) {
            // authenticator not configured
            logger.error("Duo Authenticator is missing Secret Key configuration!  All authentications will fail.");
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        String duoGroups = authConfigMap.getOrDefault(DuoUniversalAuthenticatorFactory.DUO_GROUPS, "none");

        UserModel user;
        if (authConfigMap.getOrDefault(DuoUniversalAuthenticatorFactory.DUO_USE_IMPERSONATOR, "false").equalsIgnoreCase("true")) {
            user = this.getImpersonatorOrUser(authenticationFlowContext);
        } else {
            user = authenticationFlowContext.getUser();
        }

        if (user == null) {
            // no username
            logger.error("Received a flow request with no user!  Returning internal error.");
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        String username = user.getUsername();
        if (!duoRequired(duoGroups, user)) {
            String userGroupsStr = user.getGroupsStream().map(GroupModel::getName).collect(Collectors.joining(","));
            logger.infof("Skipping Duo MFA for %s based on group membership, groups=%s", username, userGroupsStr);
            authenticationFlowContext.success();
            return;
        }

        // determine the user desire
        // if a duo state is set, assume it is the second request
        boolean firstRequest = !(authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_STATE") != null && !authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_STATE").isEmpty());

        if (firstRequest) {
            // send client to duo to authenticate
            this.startDuoProcess(authenticationFlowContext, username);
        } else {
            // handle duo response
            String loginState = authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_STATE");
            String loginUsername = authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_USERNAME");

            MultivaluedMap<String, String> queryParams = authenticationFlowContext.getUriInfo().getQueryParameters();
            if (queryParams.containsKey("state") && queryParams.containsKey("duo_code")) {
                String state = queryParams.getFirst("state");
                String duoCode = queryParams.getFirst("duo_code");

                String redirectUrl = getRedirectUrl(authenticationFlowContext);

                boolean authSuccess = false;
                try {
                    Client duoClient = this.initDuoClient(authenticationFlowContext, redirectUrl);
                    Token token = duoClient.exchangeAuthorizationCodeFor2FAResult(duoCode, username);

                    if (token != null && token.getAuth_result() != null) {
                        if (token.getAuth_result().getStatus().equalsIgnoreCase("allow")) {
                            authSuccess = true;
                        }
                    }
                } catch (DuoException exception) {
                    logger.warn("There was a problem exchanging the Duo token.  Returning start page.");
                    this.startDuoProcess(authenticationFlowContext, username);
                    return;
                }

                if (!loginState.equalsIgnoreCase(state)) {
                    // sanity check the session
                    logger.warn("Login state did not match saved value.  Returning start page.");
                    this.startDuoProcess(authenticationFlowContext, username);
                    return;
                }
                if (!username.equalsIgnoreCase(loginUsername)) {
                    // sanity check the session
                    logger.warnf("Duo username (%s) did not match saved value (%s).  Returning start page.", loginUsername, username);
                    this.startDuoProcess(authenticationFlowContext, username);
                    return;
                }

                if (authSuccess) {
                    authenticationFlowContext.success();
                } else {
                    LoginFormsProvider provider = authenticationFlowContext.form().addError(new FormMessage(null, "You did not pass multifactor verification."));
                    authenticationFlowContext.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, provider.createErrorPage(Response.Status.FORBIDDEN));
                }
            } else {
                // missing required information
                logger.warn("Received a Duo callback that was missing information.  Starting over.");
                this.startDuoProcess(authenticationFlowContext, username);
            }
        }
    }

    private void startDuoProcess(AuthenticationFlowContext authenticationFlowContext, String username) {
        AuthenticatorConfigModel authConfig = authenticationFlowContext.getAuthenticatorConfig();
        // authConfig should be safe at this point, as it will be checked in the calling method

        String redirectUrl = getRedirectUrl(authenticationFlowContext, true);
        Client duoClient;

        try {
            duoClient = this.initDuoClient(authenticationFlowContext, redirectUrl);
            duoClient.healthCheck();
        } catch (DuoException exception) {
            // Duo is not available
            logger.warn("Authentication against Duo failed with exception: " + exception);
            if (authConfig.getConfig().getOrDefault(DuoUniversalAuthenticatorFactory.DUO_FAIL_SAFE, "false").equalsIgnoreCase("false")) {
                // fail secure, deny login
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            } else {
                authenticationFlowContext.success();
            }
            return;
        }

        String loginState = duoClient.generateState();
        authenticationFlowContext.getAuthenticationSession().setAuthNote("DUO_STATE", loginState);
        authenticationFlowContext.getAuthenticationSession().setAuthNote("DUO_USERNAME", username);

        try {
            String startingUrl = duoClient.createAuthUrl(username, loginState);
            authenticationFlowContext.challenge(Response.temporaryRedirect(new URI(startingUrl)).build());
        } catch (Exception exception) {
            if (authConfig.getConfig().getOrDefault(DuoUniversalAuthenticatorFactory.DUO_FAIL_SAFE, "true").equalsIgnoreCase("false")) {
                // fail secure, deny login
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            } else {
                authenticationFlowContext.success();
            }
        }
    }

    private boolean duoRequired(String duoGroups, UserModel user) {
        if (duoGroups == null || duoGroups.isBlank() || duoGroups.strip().equals("none")) {
            return true;
        }

        List<String> groups = Arrays.asList(duoGroups.split(","));
        return user.getGroupsStream().anyMatch(g -> groups.contains(g.getName()));
    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {

    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public void close() {

    }
}

package com.instipod.duouniversal;

import com.duosecurity.Client;
import com.duosecurity.exception.DuoException;
import com.duosecurity.model.Token;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;

public class DuoUniversalAuthenticator implements org.keycloak.authentication.Authenticator {
    public static final DuoUniversalAuthenticator SINGLETON = new DuoUniversalAuthenticator();
    private static Logger logger = Logger.getLogger(DuoUniversalAuthenticator.class);

    private Client initDuoClient(AuthenticatorConfigModel authConfig, String redirectUrl) throws DuoException {
        Client client = new Client.Builder(authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_INTEGRATION_KEY), authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_SECRET_KEY), authConfig.getConfig().get(DuoUniversalAuthenticatorFactory.DUO_API_HOSTNAME), redirectUrl).build();
        return client;
    }

    @Override
    public void authenticate(AuthenticationFlowContext authenticationFlowContext) {
        AuthenticatorConfigModel authConfig = authenticationFlowContext.getAuthenticatorConfig();

        if (authConfig.getConfig().getOrDefault(DuoUniversalAuthenticatorFactory.DUO_API_HOSTNAME, "none").equalsIgnoreCase("none")) {
            //authenticator not configured
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
        if (authConfig.getConfig().getOrDefault(DuoUniversalAuthenticatorFactory.DUO_INTEGRATION_KEY, "none").equalsIgnoreCase("none")) {
            //authenticator not configured
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }
        if (authConfig.getConfig().getOrDefault(DuoUniversalAuthenticatorFactory.DUO_SECRET_KEY, "none").equalsIgnoreCase("none")) {
            //authenticator not configured
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
        }

        UserModel user = authenticationFlowContext.getUser();
        if (user == null) {
            //no username
            logger.error("Received a flow request with no user!  Returning internal error.");
            authenticationFlowContext.failure(AuthenticationFlowError.INTERNAL_ERROR);
            return;
        }
        String username = user.getUsername();

        boolean firstRequest = true;
        //determine the user desire
        //if a duo state is set, assume it is the second request
        firstRequest = !(authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_STATE") != "" && authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_STATE") != null);

        if (firstRequest) {
            //send client to duo to authenticate
            this.startDuoProcess(authenticationFlowContext, username);
            return;
        } else {
            //handle duo response
            String loginState = authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_STATE");
            String loginUsername = authenticationFlowContext.getAuthenticationSession().getAuthNote("DUO_USERNAME");

            MultivaluedMap<String, String> queryParams = authenticationFlowContext.getHttpRequest().getUri().getQueryParameters();
            if (queryParams.containsKey("state") && queryParams.containsKey("duo_code")) {
                String state = queryParams.getFirst("state");
                String duoCode = queryParams.getFirst("duo_code");

                String redirectUrl = authenticationFlowContext.getRefreshUrl(false).toString();

                boolean authSuccess = false;
                try {
                    Client duoClient = this.initDuoClient(authConfig, redirectUrl);
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
                    //sanity check the session
                    this.startDuoProcess(authenticationFlowContext, username);
                    return;
                }
                if (!username.equalsIgnoreCase(loginUsername)) {
                    //sanity check the session
                    this.startDuoProcess(authenticationFlowContext, username);
                    return;
                }

                if (authSuccess) {
                    authenticationFlowContext.success();
                } else {
                    LoginFormsProvider provider = authenticationFlowContext.form().addError(new FormMessage(null, "You did not pass multifactor verification."));
                    authenticationFlowContext.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, provider.createErrorPage(Response.Status.FORBIDDEN));
                }
                return;
            } else {
                //missing required information
                logger.warn("Received a Duo callback that was missing information.  Starting over.");
                this.startDuoProcess(authenticationFlowContext, username);
                return;
            }
        }
    }

    private void startDuoProcess(AuthenticationFlowContext authenticationFlowContext, String username) {
        AuthenticatorConfigModel authConfig = authenticationFlowContext.getAuthenticatorConfig();

        String redirectUrl = authenticationFlowContext.getRefreshUrl(false).toString();
        Client duoClient;

        try {
            duoClient = this.initDuoClient(authConfig, redirectUrl);
            duoClient.healthCheck();
        } catch (DuoException exception) {
            //Duo is not available
            logger.warn("Duo was not reachable!");
            if (authConfig.getConfig().getOrDefault(DuoUniversalAuthenticatorFactory.DUO_FAIL_SAFE, "true").equalsIgnoreCase("false")) {
                //fail secure, deny login
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
                //fail secure, deny login
                authenticationFlowContext.failure(AuthenticationFlowError.INVALID_CREDENTIALS);
            } else {
                authenticationFlowContext.success();
            }
        }
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

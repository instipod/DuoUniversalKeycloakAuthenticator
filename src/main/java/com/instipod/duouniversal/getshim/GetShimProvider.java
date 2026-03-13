package com.instipod.duouniversal.getshim;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;
import org.owasp.encoder.Encode;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

public class GetShimProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public GetShimProvider(KeycloakSession session) {
        this.session = session;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Override
    public Object getResource() {
        return this;
    }

    @GET
    @Path("/callback")
    @Produces(MediaType.TEXT_HTML)
    public Response get() {
        KeycloakContext context = session.getContext();
        String realm = "";

        try {
            realm = context.getRealm().getName();
        } catch (Exception exception) {
            // leave realm blank
        }

        UriInfo uriInfo = context.getUri();
        MultivaluedMap<String, String> queryParams = uriInfo.getQueryParameters();
        if (realm.equalsIgnoreCase("") || !queryParams.containsKey("kc_execution") || !queryParams.containsKey("kc_client_id") || !queryParams.containsKey("kc_tab_id")) {
            // these fields are required, throw a bad request error
            return Response.status(400).build();
        }

        String authenticationExecution = queryParams.getFirst("kc_execution");
        String clientId = queryParams.getFirst("kc_client_id");
        String tabId = queryParams.getFirst("kc_tab_id");

        String actionUrl = uriInfo.getBaseUri().toString() + "realms/" + urlEncode(realm);
        actionUrl = actionUrl + "/login-actions/authenticate";
        actionUrl = actionUrl + "?execution=" + urlEncode(authenticationExecution);
        actionUrl = actionUrl + "&client_id=" + urlEncode(clientId);
        actionUrl = actionUrl + "&tab_id=" + urlEncode(tabId);

        if (!queryParams.containsKey("kc_session_code") || !queryParams.containsKey("state") || !queryParams.containsKey("duo_code")) {
            // session code is required, redirect back to beginning of auth flow
            // or if they don't have duo information, send them to beginning as well
            try {
                return Response.temporaryRedirect(new URI(actionUrl)).build();
            } catch (URISyntaxException exception) {
                return Response.serverError().build();
            }
        }

        String sessionCode = queryParams.getFirst("kc_session_code");
        String state = queryParams.getFirst("state");
        String duoCode = queryParams.getFirst("duo_code");

        actionUrl = actionUrl + "&session_code=" + urlEncode(sessionCode);
        actionUrl = actionUrl + "&state=" + urlEncode(state);
        actionUrl = actionUrl + "&duo_code=" + urlEncode(duoCode);

        LoginFormsProvider forms = session.getProvider(LoginFormsProvider.class);
        forms.setAttribute("actionUrl", Encode.forHtmlAttribute(actionUrl));
        forms.setAttribute("authenticationExecution", Encode.forHtmlAttribute(authenticationExecution));
        return forms.createForm("duo-universal-callback.ftl");
    }

    @Override
    public void close() {
    }
}
package com.instipod.duouniversal.getshim;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import java.net.URI;
import java.net.URISyntaxException;

public class GetShimProvider implements RealmResourceProvider {
    private final KeycloakSession session;

    public GetShimProvider(KeycloakSession session) {
        this.session = session;
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
        String actionUrl = uriInfo.getBaseUri().toString() + "realms/" + realm + "/login-actions/authenticate";
        actionUrl = actionUrl + "?execution=" + authenticationExecution;
        actionUrl = actionUrl + "&client_id=" + clientId;
        actionUrl = actionUrl + "&tab_id=" + tabId;

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

        actionUrl = actionUrl + "&session_code=" + sessionCode;
        actionUrl = actionUrl + "&state=" + state;
        actionUrl = actionUrl + "&duo_code=" + duoCode;

        String redirect = "<html><body onload=\"document.forms[0].submit()\"><form id=\"form1\" action=\"" + actionUrl + "\" method=\"post\"><input type=\"hidden\" name=\"authenticationExecution\" value=\"" + authenticationExecution + "\"><noscript><input type=\"submit\" value=\"Continue\"></noscript></form></body></html>";
        return Response.ok(redirect).build();
    }

    @Override
    public void close() {
    }
}
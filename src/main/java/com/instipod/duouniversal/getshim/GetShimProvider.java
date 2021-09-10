package com.instipod.duouniversal.getshim;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.*;
import java.net.URI;
import java.net.URISyntaxException;

public class GetShimProvider implements RealmResourceProvider {
    private KeycloakSession session;

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
    public Response get(@Context UriInfo uriInfo) {
        String realm = "";
        try {
            realm = uriInfo.getPath().split("realms/")[1].split("/")[0];
        } catch (Exception exception) {
            //leave realm blank
        }

        MultivaluedMap<String, String> queryParams = uriInfo.getQueryParameters();
        if (realm.equalsIgnoreCase("") || !queryParams.containsKey("kc_execution") || !queryParams.containsKey("kc_client_id") || !queryParams.containsKey("kc_tab_id")) {
            //these fields are required, throw a bad request error
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
            //session code is required, redirect back to beginning of auth flow
            //or if they don't have duo information, send them to beginning as well
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
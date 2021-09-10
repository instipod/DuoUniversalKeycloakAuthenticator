package com.instipod.duouniversal.getshim;

import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
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
    public Response get(@Context UriInfo uriInfo) throws URISyntaxException {
        //authenticationExecution
        String realm = uriInfo.getPath().toString().split("realms/")[1].split("/")[0];

        String authenticationExecution = uriInfo.getQueryParameters().getFirst("kc_execution");
        String clientId = uriInfo.getQueryParameters().getFirst("kc_client_id");
        String tabId = uriInfo.getQueryParameters().getFirst("kc_tab_id");
        String sessionCode = uriInfo.getQueryParameters().getFirst("kc_session_code");
        String state = uriInfo.getQueryParameters().getFirst("state");
        String duoCode = uriInfo.getQueryParameters().getFirst("duo_code");

        String actionUrl = uriInfo.getBaseUri().toString() + "realms/" + realm + "/login-actions/authenticate";
        actionUrl = actionUrl + "?execution=" + authenticationExecution;
        actionUrl = actionUrl + "&client_id=" + clientId;
        actionUrl = actionUrl + "&tab_id=" + tabId;
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
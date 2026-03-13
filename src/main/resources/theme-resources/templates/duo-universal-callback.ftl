<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "header">
        ${msg("saml.post-form.title")}
    <#elseif section = "form">
        <script>window.onload = function() {document.forms[0].submit()};</script>
        <p>${msg("saml.post-form.message")}</p>
        <form name="duo-post-binding" method="post" action="${actionUrl}">
            <#if authenticationExecution??>
                <input type="hidden" name="authenticationExecution" value="${authenticationExecution}"/>
            </#if>

            <noscript>
                <p>${msg("saml.post-form.js-disabled")}</p>
                <input type="submit" value="${msg("doContinue")}"/>
            </noscript>
        </form>
    </#if>
</@layout.registrationLayout>
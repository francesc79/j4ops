
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt_rt"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<form:form method="POST" action="/config/save.htm" modelAttribute="config">
    <table class="list-table">
        <thead>
            <tr>
                <td>Property</td>
                <td>Value</td>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><form:label path="verifyCertificate"><spring:message code="config.property.verify_certificate" text="default" /></form:label></td>
                <td>
                    <form:select path="verifyCertificate">
                        <form:option value="true" />
                        <form:option value="false" />
                    </form:select>
                </td>
            </tr>
            <tr>
                <td><form:label path="verifyCRL"><spring:message code="config.property.verify_crl" text="default" /></form:label></td>
                <td>
                    <form:select path="verifyCRL">
                        <form:option value="true" />
                        <form:option value="false" />
                    </form:select>
                </td>
            </tr>
            <tr>
                <td><form:label path="envelopeEncode"><spring:message code="config.property.envelope_encode" text="default" /></form:label></td>
                <td>
                    <form:select path="envelopeEncode">
                        <form:option value="DER" />
                        <form:option value="B64" />
                    </form:select>
                </td>
            </tr>
            <tr>
                <td><form:label path="encryptionAlgName"><spring:message code="config.property.encryption_alg_name" text="default" /></form:label></td>
                <td>
                    <form:select path="encryptionAlgName">
                        <form:option value="RSA" />
                    </form:select>
                </td>
            </tr>
            <tr>
                <td><form:label path="securityProvider"><spring:message code="config.property.security_provider" text="default" /></form:label></td>
                <td>
                    <form:select path="securityProvider">
                        <form:option value="BC" />
                    </form:select>
                </td>
            </tr>
            <tr>
                <td><form:label path="PKCS12KeyStore"><spring:message code="config.property.pkcs12_keystore" text="default" /></form:label></td>
                <td>
                    <form:input path="PKCS12KeyStore" />
                </td>
            </tr>
            <tr>
                <td><form:label path="PKCS11Tokens"><spring:message code="config.property.pkcs11_tokens" text="default" /></form:label></td>
                <td>
                    <form:input path="PKCS11Tokens" />
                </td>
            </tr>
            <tr>
                <td><form:label path="fileKeyStoreTrustedRootCerts"><spring:message code="config.property.file_keystore_trusted_root_certs" text="default" /></form:label></td>
                <td>
                    <form:input path="fileKeyStoreTrustedRootCerts" />
                </td>
            </tr>
            <tr>
                <td><form:label path="passKeyStoreTrustedRootCerts"><spring:message code="config.property.pass_keystore_trusted_root_certs" text="default" /></form:label></td>
                <td>
                    <form:input path="passKeyStoreTrustedRootCerts" />
                </td>
            </tr>

            <tr>
                <td><form:label path="TSAURL"><spring:message code="config.property.tsa_url" text="default" /></form:label></td>
                <td>
                    <form:input path="TSAURL" />
                </td>
            </tr>
            <tr>
                <td><form:label path="TSAUser"><spring:message code="config.property.tsa_user" text="default" /></form:label></td>
                <td>
                    <form:input path="TSAUser" />
                </td>
            </tr>
            <tr>
                <td><form:label path="TSAPassword"><spring:message code="config.property.tsa_password" text="default" /></form:label></td>
                <td>
                    <form:input path="TSAPassword" />
                </td>
            </tr>
        </tbody>
    </table>

    <c:if test="${not empty message}">
        <div class="div-message">
            ${message}
        </div>
    </c:if>

    <spring:message code="config.form.submit" var="submitText"/>
    <input type="submit" value="${submitText}"/>
</form:form>

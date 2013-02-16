
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt_rt"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<fieldset>
    <legend><spring:message code="index.sign.legend" /></legend>

    <form:form method="POST" action="/sign.htm" modelAttribute="sign">
        <table class="list-table">
            <thead>
                <tr>
                    <td><spring:message code="index.doc_table.header.index" /></td>
                    <td><spring:message code="index.doc_table.header.selected" /></td>
                    <td><spring:message code="index.doc_table.header.name" /></td>
                    <td><spring:message code="index.doc_table.header.size" /></td>
                    <td><spring:message code="index.doc_table.header.last_modified" /></td>
                    <td><spring:message code="index.doc_table.header.operations" /></td>
                </tr>
            </thead>
            <tbody>
                <c:if test="${not empty sign.documentList}">
                    <c:forEach items="${sign.documentList}" var="document" varStatus="status">
                        <tr>
                            <td>${status.index}</td>
                            <td><form:checkbox path="documentList[${status.index}].checked" /></td>
                            <td><form:hidden path="documentList[${status.index}].name" />${document.name}</td>
                            <td><fmt:formatNumber value="${document.size}" pattern="#,##0.#" /></td>
                            <td><fmt:formatDate value="${document.lastModified}" pattern="dd-MM-yyyy hh:mm:ss" /></td>
                            <td><a class="verify" href="<c:url value="/verify/${document.name}" />"><spring:message code="index.doc_table.operation.verify" /></a>&nbsp;<a href="<c:url value="/delete/document/${document.name}" />"><spring:message code="index.doc_table.operation.remove" /></a></td>
                        </tr>
                    </c:forEach>
                </c:if>
            </tbody>
        </table>
        <a href="<c:url value="/upload/document.htm" />" class ="nyroModal"><spring:message code="index.upload.document" /></a>

        <table class="list-table">
            <thead>
                <tr>
                    <td colspan="2"><spring:message code="index.options.title"  /></td>
                </tr>
            </thead>
            <tbody>
                <tr id="rowEnvelopeSignType">
                    <td>
                        <form:label path="envelopeSignType"><spring:message code="index.options.envelope_sign_type" /></form:label>
                    </td>
                    <td>
                        <form:select path="envelopeSignType">
                            <form:option value="Pkcs7" />
                            <form:option value="CAdES_BES" />
                            <form:option value="CAdES_T" />
                            <form:option value="PDF" />
                            <form:option value="PAdES_BES" />
                            <form:option value="PAdES_T" />
                            <form:option value="XMLDSIG" />
                            <form:option value="XAdES_BES" />
                            <form:option value="XAdES_T" />
                        </form:select>
                    </td>
                </tr>
                <tr id="rowSignMode">
                    <td>
                        <form:label path="signMode"><spring:message code="index.options.sign_mode" /></form:label>
                    </td>
                    <td>
                        <form:select path="signMode">
                            <form:option value="Attached" />
                            <form:option value="Detached" />
                        </form:select>
                    </td>
                </tr>
                <tr id="rowXmlSignMode">
                    <td>
                        <form:label path="xmlSignMode"><spring:message code="index.options.xml_sign_mode" /></form:label>
                    </td>
                    <td>
                        <form:select path="xmlSignMode">
                            <form:option value="Enveloped" />
                            <form:option value="Enveloping" />
                            <form:option value="Detached" />
                        </form:select>
                    </td>
                </tr>
                <tr id="rowAddSignInfo">
                    <td>
                        <form:label path="addSignInfo"><spring:message code="index.options.add_sign_info" /></form:label>
                    </td>
                    <td>
                        <form:select path="addSignInfo">
                            <form:option value="true" />
                            <form:option value="false" />
                        </form:select>
                    </td>
                </tr>
            </tbody>
        </table>

        <form:hidden path="action" />

        <table class="list-table">
            <thead>
                <tr>
                    <td><spring:message code="index.actions.title" /></td>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>
                        <spring:message code="index.form.submit.sign" var="submitSign"/>
                        <input id="action-sign" type="submit" value="${submitSign}"/>
                        <spring:message code="index.form.submit.add_sign" var="submitAddSign"/>
                        <input id="action-add-sign" type="submit" value="${submitAddSign}"/>
                        <spring:message code="index.form.submit.counter_sign" var="submitCounterSign"/>
                        <input id="action-counter-sign" type="submit" value="${submitCounterSign}"/>
                    </td>
                </tr>
            </tbody>
        </table>
    </form:form>
</fieldset>

<c:if test="${not empty error}">
    <div class="div-error"><spring:message code="index.siged.error" />&nbsp;${error}</div>
</c:if>

<div id="loading" style="display:none;"><img src="<c:url value="/resources/js/nyroModal/images/ajaxLoader.gif" />"/></div>

<script type="text/javascript">
    $(document).ready(function () {
        $('.nyroModal').nyroModal({
            callbacks: {
                initFilters: function(nm) {
                    nm.filters.push('link');
                    nm.filters.push('iframe');
                }
            }
        });
        $('#envelopeSignType').change(function() {
            switch ($(this).val()) {
                case 'Pkcs7':
                case 'CAdES_BES':
                case 'CAdES_T':
                case 'PDF':
                case 'PAdES_BES':
                case 'PAdES_T':

                    $("#rowSignMode").show();
                    $("#rowXmlSignMode").hide();
                    break;

                case 'XMLDSIG':
                case 'XAdES_BES':
                case 'XAdES_T':

                    $("#rowSignMode").hide();
                    $("#rowXmlSignMode").show();
                    break;
            }
        });
        $('#envelopeSignType').change();


        $("#action-sign").click(function() {
            $("#action-action").val("SIGN");
            $("#sign").submit();
        });
        $("#action-add-sign").click(function() {
            $("#action").val("ADD_SIGN");
            $("#sig").submit();
        });
        $("#action-counter-sign").click(function() {
            $("#action").val("COUNTER_SIGN");
            $("#sign").submit();
        });

        $('.verify').click(function() {
            $("#loading").css("display", "inline");
            $("#loading").offset({
                top: $(document).height()/2 -  $("#loading").height()/2,
                left: $(document).width()/2 -  $("#loading").width()/2
            })
            $(this).load($(this).attr('href'));
        });
    });

</script>


<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt_rt"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title><spring:message code="index.title" text="default" /></title>
    <link rel="stylesheet" type="text/css" href="<c:url value="/resources/css/style.css" />">
</head>
<body>
    <div id="header">
    </div>
    <div id="content">

        <form:form method="POST" action="/sign.htm" modelAttribute="signForm">
            <table>
                <thead>
                    <tr>
                        <td>Index</td>
                        <td>Name</td>
                        <td>Size</td>
                        <td>Last Modified</td>
                        <td>Flag</td>
                    </tr>
                </thead>
                <tbody>
                    <c:if test="${not empty signForm.documentList}">
                        <c:forEach items="${signForm.documentList}" var="document" varStatus="status">
                            <tr>
                                <td>${status.index}</td>
                                <td><form:hidden path="documentList[${status.index}].name" />${document.name}</td>
                                <td><fmt:formatNumber value="${document.size}" pattern="#,##0.#" /></td>
                                <td><fmt:formatDate value="${document.lastModified}" pattern="dd-MM-yyyy hh:mm:ss" /></td>
                                <td><form:checkbox path="documentList[${status.index}].checked" /></td>
                            </tr>
                        </c:forEach>
                    </c:if>
                </tbody>
            </table>

            <form:select path="signType">
                <form:option value="CAdES_BES" />
                <form:option value="PAdES_BES" />
                <form:option value="XAdES_BES" />
            </form:select>

            <form:select path="addSignInfo">
                <form:option value="true" />
                <form:option value="false" />
            </form:select>

            <input type="submit" value="Sign"/>

        </form:form>

        <form:form method="post" action="/uploadDocument.htm"
                   modelAttribute="uploadForm" enctype="multipart/form-data">
            <input name="files[0]" type="file" />
            <input type="submit" value="Upload" />
        </form:form>

        <c:if test="${not empty error}">
            <p>Error:${error}</p>
        </c:if>

        <c:if test="${not empty signedDocumentList}">
            <table>
                <thead>
                    <tr>
                        <td>Index</td>
                        <td>Name</td>
                        <td>Size</td>
                        <td>Last Modified</td>
                        <td>Flag</td>
                    </tr>
                </thead>
                <tbody>
                    <c:forEach items="${signedDocumentList}" var="document" varStatus="status">
                        <tr>
                            <td>${status.index}</td>
                            <td>${document.name}</td>
                            <td><fmt:formatNumber value="${document.size}" pattern="#,##0.#" /></td>
                            <td><fmt:formatDate value="${document.lastModified}" pattern="dd-MM-yyyy HH:mm:ss" /></td>
                            <td></td>
                        </tr>
                    </c:forEach>
                </tbody>
            </table>
        </c:if>


    </div>
    <div id="footer">
    </div>
</body>
</html>
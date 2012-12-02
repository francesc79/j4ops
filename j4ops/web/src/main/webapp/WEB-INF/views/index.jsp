
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
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

    <table>
        <thead>
            <tr>
                <td>Index</td>
                <td>Name</td>
                <td>Size</td>
                <td>Last Modified</td>
            </tr>
        </thead>
        <tbody>
            <c:if test="${not empty listDocument}">
                <c:forEach items="${listDocument}" var="${document}" varStatus="${status}">
                    <tr>
                        <td>${status.index}</td>
                        <td>${document.name}</td>
                        <td>${document.size}</td>
                        <td>${document.lastModified}</td>
                    </tr>
                </c:forEach>
            </c:if>
        </tbody>
    </table>


    <a href="/sign.htm">sign</a>



    </div>
    <div id="footer">
    </div>
</body>
</html>
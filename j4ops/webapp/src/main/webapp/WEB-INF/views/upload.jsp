<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title><spring:message code="upload.title"/></title>
    <style type="text/css" media="screen,projection">
        @import "<c:url value="/resources/css/screen.css" />";
    </style>
    <link rel="stylesheet" type="text/css" href="<c:url value="/resources/js/nyroModal/nyroModal.css" />" />
    <script type="text/javascript" src="<c:url value="/resources/js/jquery-1.8.2.min.js" />"></script>
    <script type="text/javascript" src="<c:url value="/resources/js/nyroModal/jquery.nyroModal.custom.min.js" />"></script>
    <!--[if lte IE 6]>
    <script type="text/javascript" src="<c:url value="/resources/js/nyroModal/jquery.nyroModal-ie6.min.js" />"></script>
    <![endif]-->
</head>
<body>
    <fieldset>
        <legend><spring:message code="upload.legend" /></legend>
        <form:form method="post" action="${path}"
                   modelAttribute="upload" enctype="multipart/form-data">
            <input name="files[0]" type="file" />

            <spring:message code="upload.form.submit" var="submitText"/>
            <input type="submit" value="${submitText}" />
        </form:form>
    </fieldset>

    <c:if test="${not empty close}">
        <script type="text/javascript">
            $(document).ready(function () {
                parent.window.location.reload();
                parent.$.nmTop().close();
            });
        </script>
    </c:if>
</body>
</html>
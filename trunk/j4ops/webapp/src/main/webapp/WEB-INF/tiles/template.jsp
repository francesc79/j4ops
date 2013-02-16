<%@ taglib uri="http://tiles.apache.org/tags-tiles" prefix="tiles" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.springframework.org/tags" prefix="spring" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">

        <style type="text/css" media="screen,projection">
            @import "<c:url value="/resources/css/screen.css" />";
        </style>
        <link rel="stylesheet" type="text/css" media="print" href="<c:url value="/resources/css/print.css" />">
        <!--[if lte IE 6]>
        <style type="text/css" media="screen,projection">
            @import "<c:url value="/resources/css/ieminwidth.css" />";
        </style>
        <![endif]-->

        <script type="text/javascript" src="<c:url value="/resources/js/deployJava.js" />"></script>
        <script type="text/javascript" src="<c:url value="/resources/js/jquery-1.8.2.min.js" />"></script>

        <link rel="stylesheet" type="text/css" href="<c:url value="/resources/js/treeview/jquery.treeview.css" />">
        <script type="text/javascript" src="<c:url value="/resources/js/treeview/jquery.treeview.js" />"></script>

        <link rel="stylesheet" type="text/css" href="<c:url value="/resources/js/nyroModal/nyroModal.css" />">
        <script type="text/javascript" src="<c:url value="/resources/js/nyroModal/jquery.nyroModal.custom.min.js" />"></script>
        <!--[if lte IE 6]>
            <script type="text/javascript" src="<c:url value="/resources/js/nyroModal/jquery.nyroModal-ie6.min.js" />"></script>
        <![endif]-->

        <c:set var="titleKey">
            <tiles:insertAttribute name="title" ignore="true" />
        </c:set>
        <title><spring:message code="${titleKey}" /></title>
    </head>
    <body>
        <div id="container">
            <div id="header">
                <tiles:insertAttribute name="header" />
                <a id="skipnav" href="#startcontent">go to content</a>
            </div>
            <div id="sidebar">
                <tiles:insertAttribute name="sidebar" ignore="true"/>
            </div>
            <div id="content">
                <a name="startcontent" id="startcontent"></a>
                <tiles:insertAttribute name="content" />
            </div>
            <div id="footer">
                <tiles:insertAttribute name="footer" />
            </div>
        </div>
    </body>
</html>

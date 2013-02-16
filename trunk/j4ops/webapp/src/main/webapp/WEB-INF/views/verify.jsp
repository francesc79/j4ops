<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt_rt"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>
<%@ taglib prefix="tags" tagdir="/WEB-INF/tags" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<div id="signers">
    <c:if test="${not empty verifyInfo}">
        <c:if test="${not empty verifyInfo.signerInfos}">
            <tags:verify id="treeviewSigners" listSignerInfo="${verifyInfo.signerInfos}" />
        </c:if>
    </c:if>
</div>

<div id="sign_content">
    <c:if test="${not empty fileView}">
        <iframe src="${fileView}#toolbar=0&amp;navpanes=0"/>
    </c:if>
</div>

<script type="text/javascript">
    $(document).ready(function () {
        $("#treeviewSigners").treeview();
    });
</script>


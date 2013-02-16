<%@ tag description="verify tag" pageEncoding="UTF-8"%>
<%@ attribute name="listSignerInfo" type="java.util.ArrayList<it.j4ops.verify.bean.SignerInfo>" required="true" %>
<%@ attribute name="id" type="java.lang.String" required="true" %>
<%@ taglib prefix="tags" tagdir="/WEB-INF/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt_rt"%>

<c:if test="${not empty listSignerInfo}">
    <ul id="${id}">
        <c:forEach items="${listSignerInfo}" var="signer" varStatus="status">
            <li>${signer.author}&nbsp;<fmt:formatDate value="${signer.dateSign}" pattern="dd-MM-yyyy hh:mm:ss" /></li>
            <tags:verify id="" listSignerInfo="${signer.signerInfos}" />
        </c:forEach>
    </ul>
</c:if>


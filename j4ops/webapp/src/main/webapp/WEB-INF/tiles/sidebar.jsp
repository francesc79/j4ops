<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"  %>
<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>

<p>
    <a href="<c:url value="/index.htm"/>"><spring:message code="menu.index" /></a>
</p>
<sec:authorize access="hasRole('ROLE_ADMIN')">
<p>
    <a href="<c:url value="/config.htm"/>"><spring:message code="menu.config" /></a>
</p>
</sec:authorize>
<p>
    <a href="<c:url value="/logout.htm"/>"><spring:message code="menu.logout" /></a>
</p>
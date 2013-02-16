<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jstl/fmt_rt"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<form id="login-form" action="j_spring_security_check" method="post" >
    <p>
        <label for="j_username"><spring:message code="login.form.username" /></label>&nbsp;<input id="j_username" name="j_username" type="text" />
    </p>
    <p>
        <label for="j_password"><spring:message code="login.form.password" /></label>&nbsp;<input id="j_password" name="j_password" type="password" />
    </p>
    <spring:message code="login.form.submit" var="submitText"/>
    <input  type="submit" value="${submitText}" />
</form>

<c:if test="${not empty error}">
    <div class="div-error">
        Your login attempt was not successful, try again.<br />
            ${sessionScope["SPRING_SECURITY_LAST_EXCEPTION"].message}
    </div>
</c:if>

<script type="text/javascript">
    $(document).ready(function () {
        $("#j_username").focus();
    });
</script>

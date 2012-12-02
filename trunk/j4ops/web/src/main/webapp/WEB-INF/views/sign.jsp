<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
<head>
    <title><spring:message code="sign.title" text="default" /></title>
    <link rel="stylesheet" type="text/css" href="<c:url value="/resources/css/style.css" />">
    <script type="text/javascript" src="<c:url value="/resources/js/deployJava.js" />"></script>
    <script type="text/javascript" src="<c:url value="/resources/js/jquery-1.8.2.min.js" />"></script>
</head>
<body>

<script type="text/javascript">
    $(document).ready (function(){
        var attributes = { id:'j4opsApplet', code:'it.j4ops.gui.J4OPSApplet.class', width:1, height:1};
        var parameters = {
            archive: function() {
                var jars_base = ['j4ops-applet-1.0.0.jar',      'lib/activation-1.1.jar',
                                 'lib/bcmail-jdk16-1.46.jar',   'lib/bcprov-jdk16-1.46.jar',
                                 'lib/bctsp-jdk16-1.46.jar',    'lib/commons-httpclient-3.1.jar',
                                 'lib/commons-lang-2.6.jar',    'lib/commons-logging-1.1.1.jar',
                                 'lib/j4ops-core-1.0.0.jar',    'lib/j4ops-gui-1.0.0.jar',
                                 'lib/log4j-1.2.15.jar',        'lib/mail-1.4.4.jar'];
                var jars_cades = [];
                var jars_pades = ['lib/itextpdf-5.1.3.jar'];
                var jars_xades = ['lib/serializer-2.7.1.jar',   'lib/xalan-2.7.1.jar',
                                  'lib/xml-apis-1.3.04.jar',    'lib/xmlsec-1.5.0.jar'];

                var urlBase = <c:url value="/resources/applet/" />

                var jars = [];
                var index = 0;
                for (i = 0; i < jars_base; i ++, index++) {
                    jars[index] = urlBase + jars_base[i];
                }

                return jars;
            },
            Action: 'SIGN',
            DocumentURL: '',
            PostCertificateURL: '',
            PostDocumentURL: '',
            SecurityProvider: 'BC',
            FileKeyStoreTrustedRootCerts: 'certs.ks',
            PassKeyStoreTrustedRootCerts: 'j4ops',
            PKCS11Tokens: 'tokens.xml',
            EnvelopeSignType: '',
            SignMode: 'Attached',
            EnvelopeEncode: 'B64',
            EncryptionAlgName: 'RSA',
            DigestAlgName: 'SHA256',
            VerifyCRL: 'false',
            VerifyCertificate: 'true'
        } ;
        deployJava.runApplet(attributes, parameters, '1.6');
    });
</script>
</body>
</html>
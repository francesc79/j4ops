<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="form" uri="http://www.springframework.org/tags/form" %>

<%@ page contentType="text/html;charset=UTF-8" language="java" %>

<script type="text/javascript">
    $(document).ready (function(){

        var jars_base = ['j4ops-applet-1.0.0.jar',      'lib/activation-1.1.jar',
                         'lib/bcmail-jdk16-1.46.jar',   'lib/bcprov-jdk16-1.46.jar',
                         'lib/bctsp-jdk16-1.46.jar',    'lib/commons-httpclient-3.1.jar',
                         'lib/commons-lang-2.6.jar',    'lib/commons-logging-1.1.1.jar',
                         'lib/j4ops-core-1.0.0.jar',    'lib/j4ops-gui-1.0.0.jar',
                         'lib/log4j-1.2.15.jar',        'lib/mail-1.4.4.jar',
                         'lib/slf4j-log4j12-1.6.6.jar', 'lib/slf4j-api-1.6.6.jar'];
        var jars_cades = [];
        var jars_pades = ['lib/itextpdf-5.1.3.jar'];
        var jars_xades = ['lib/serializer-2.7.1.jar',   'lib/xalan-2.7.1.jar',
                          'lib/xml-apis-1.3.04.jar',    'lib/xmlsec-1.5.0.jar'];

        var urlBase = '<c:url value="/resources/applet/" />';
        var jars = null;
        for (i = 0; i < jars_base.length; i ++) {
            if (jars == null) {
                jars = urlBase + jars_base[i];
            }
            else {
                jars = jars + ',' + urlBase + jars_base[i];
            }
        }
        if ('${signType}'.match('^PAdES')) {
            for (i = 0; i < jars_pades.length; i ++) {
                jars = jars + ',' + urlBase + jars_pades[i];
            }
        }
        if ('${signType}'.match('^XAdES')) {
            for (i = 0; i < jars_pades.length; i ++) {
                jars = jars + ',' + urlBase + jars_xades[i];
            }
        }

        var attributes = { id:'j4opsApplet', code:'it.j4ops.gui.J4OPSApplet.class', width:100, height:100};
        var parameters = {
            archive: jars,
            Action: 'SIGN',
            DocumentURL: '${documentURL}',
            PostCertificateURL: '${postDocumentURL}',
            PostDocumentURL: '${postDocumentURL}',
            SecurityProvider: "${properties['SecurityProvider']}",
            FileKeyStoreTrustedRootCerts: "${properties['FileKeyStoreTrustedRootCerts']}",
            PassKeyStoreTrustedRootCerts: "${properties['PassKeyStoreTrustedRootCerts']}",
            PKCS11Tokens: "${properties['PKCS11Tokens']}",
            EnvelopeSignType: "${properties['EnvelopeSignType']}",
            SignMode: "${properties['SignMode']}",
            EnvelopeEncode: "${properties['EnvelopeEncode']}",
            EncryptionAlgName: "${properties['EncryptionAlgName']}",
            DigestAlgName: "${properties['DigestAlgName']}",
            VerifyCRL: "${properties['VerifyCRL']}",
            VerifyCertificate: "${properties['VerifyCertificate']}",
            Cookie: 'JSESSIONID=${pageContext.session.id}'
        } ;
        deployJava.runApplet(attributes, parameters, '1.6');
    });
</script>


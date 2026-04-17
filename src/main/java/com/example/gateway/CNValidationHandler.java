package com.example.gateway;

import org.apache.axis2.context.MessageContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.core.axis2.Axis2Sender;
import org.apache.synapse.rest.AbstractHandler;
import org.apache.synapse.SynapseConstants;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Custom APIM API Gateway handler for CN-based client identity validation.
 *
 * <p>Designed for multi-ingress architectures where F5 terminates mTLS and forwards
 * the client certificate via an HTTP header. The handler uses a trust zone header
 * (injected by F5) to determine whether CN validation should be enforced, allowing
 * the same gateway runtime to serve multiple ingress trust zones.
 *
 * <p>Must extend {@code org.apache.synapse.rest.AbstractHandler} — this is the correct
 * base class for APIM API gateway handlers. APIFactory casts handlers to
 * {@code org.apache.synapse.rest.Handler} at deployment time.
 *
 * <p>Handler properties (injected via Velocity template {@code <property>} elements):
 * <ul>
 *   <li>{@code certificateHeader} — HTTP header carrying the forwarded leaf cert.
 *       Default: {@code X-Client-Cert}</li>
 *   <li>{@code trustZoneHeader} — Header set by F5 to identify the ingress trust zone.
 *       Default: {@code X-WSO2-Trust-Zone}</li>
 *   <li>{@code trustZoneValue} — Expected value for internet ingress.
 *       Default: {@code internet}</li>
 *   <li>{@code allowedCns} — Comma-separated list of permitted CN values.
 *       Example: {@code ClientAppA,ClientAppB}</li>
 * </ul>
 */
public class CNValidationHandler extends AbstractHandler {

    private static final Log log = LogFactory.getLog(CNValidationHandler.class);

    // -------------------------------------------------------------------------
    // Handler properties — populated via Synapse XML <property> setter injection
    // -------------------------------------------------------------------------
    private String certificateHeader = "X-Client-Cert";
    private String trustZoneHeader   = "X-WSO2-Trust-Zone";
    private String trustZoneValue    = "internet";
    private String allowedCns        = "";

    public void setCertificateHeader(String certificateHeader) {
        this.certificateHeader = certificateHeader;
    }

    public void setTrustZoneHeader(String trustZoneHeader) {
        this.trustZoneHeader = trustZoneHeader;
    }

    public void setTrustZoneValue(String trustZoneValue) {
        this.trustZoneValue = trustZoneValue;
    }

    public void setAllowedCns(String allowedCns) {
        this.allowedCns = allowedCns;
    }

    // -------------------------------------------------------------------------
    // AbstractHandler contract
    // -------------------------------------------------------------------------

    @Override
    public boolean handleRequest(org.apache.synapse.MessageContext synCtx) {
        MessageContext axis2MC = ((Axis2MessageContext) synCtx).getAxis2MessageContext();

        @SuppressWarnings("unchecked")
        Map<String, String> headers = (Map<String, String>)
                axis2MC.getProperty(MessageContext.TRANSPORT_HEADERS);

        // --- Step 1: Trust zone gate ---
        String incomingZone = headers != null ? headers.get(trustZoneHeader) : null;
        if (!trustZoneValue.equalsIgnoreCase(incomingZone)) {
            if (log.isDebugEnabled()) {
                log.debug("CNValidationHandler: trust zone '" + incomingZone
                        + "' is not internet ingress — skipping CN validation.");
            }
            return true;
        }

        log.debug("CNValidationHandler: internet ingress detected — enforcing CN validation.");

        // --- Step 2: Read certificate header ---
        String rawCert = headers != null ? headers.get(certificateHeader) : null;
        if (rawCert == null || rawCert.isBlank()) {
            log.warn("CNValidationHandler: internet ingress but no certificate in header '"
                    + certificateHeader + "'. Rejecting.");
            return sendUnauthorized(synCtx, axis2MC, "Client certificate missing.");
        }

        // --- Step 3: Parse certificate ---
        X509Certificate cert;
        try {
            cert = parseCertificate(rawCert);
        } catch (Exception e) {
            log.warn("CNValidationHandler: failed to parse certificate — " + e.getMessage());
            return sendUnauthorized(synCtx, axis2MC, "Invalid client certificate.");
        }

        // --- Step 4: Extract CN from Subject DN ---
        String cn = extractCN(cert.getSubjectX500Principal());
        if (cn == null || cn.isBlank()) {
            log.warn("CNValidationHandler: no CN in subject DN: "
                    + cert.getSubjectX500Principal().getName());
            return sendUnauthorized(synCtx, axis2MC, "Client certificate CN missing.");
        }

        // --- Step 5: Validate CN against permitted list ---
        if (allowedCns == null || allowedCns.isBlank()) {
            log.error("CNValidationHandler: 'allowedCns' property not configured. Rejecting.");
            return sendUnauthorized(synCtx, axis2MC, "CN validation misconfigured.");
        }

        List<String> permitted = Arrays.stream(allowedCns.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());

        if (!permitted.contains(cn)) {
            log.warn("CNValidationHandler: CN '" + cn + "' not in allowed list " + permitted + ". Rejecting.");
            return sendUnauthorized(synCtx, axis2MC, "Client CN not authorized.");
        }

        log.debug("CNValidationHandler: CN '" + cn + "' authorized.");
        synCtx.setProperty("VALIDATED_CLIENT_CN", cn);
        return true;
    }

    @Override
    public boolean handleResponse(org.apache.synapse.MessageContext synCtx) {
        return true;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Parses a PEM or URL-encoded DER certificate from the F5-forwarded header value.
     *
     * <p>Handles two forwarding modes:
     * <ul>
     *   <li><b>URL-encoded PEM</b> (F5 production): the full PEM block is percent-encoded,
     *       e.g. {@code %2B} for {@code +}, {@code %2F} for {@code /}.</li>
     *   <li><b>Raw base64</b> (testing / some F5 configs): the base64 string is sent
     *       as-is without percent-encoding.</li>
     * </ul>
     *
     * <p>URLDecoder converts literal {@code +} to space, which corrupts raw base64.
     * To handle both modes safely, literal {@code +} characters are pre-escaped to
     * {@code %2B} before decoding — URLDecoder then restores them correctly in both cases.
     */
    private X509Certificate parseCertificate(String raw) throws Exception {
        // Pre-escape literal '+' so URLDecoder treats it as '+', not space.
        // This is safe whether the input is already percent-encoded (F5) or raw base64 (test).
        String safeRaw = raw.replace("+", "%2B");
        String decoded = URLDecoder.decode(safeRaw, StandardCharsets.UTF_8);

        // Strip PEM headers and all whitespace (line breaks from PEM formatting)
        decoded = decoded
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s+", "");

        byte[] derBytes = Base64.getDecoder().decode(decoded);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
    }

    /**
     * Extracts the CN value from an X500Principal Subject DN (RFC 2253 format).
     */
    private String extractCN(X500Principal principal) {
        String dn = principal.getName(X500Principal.RFC2253);
        for (String part : dn.split(",")) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase().startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }

    /**
     * Sends a 401 Unauthorized response back to the client and stops handler chain.
     *
     * <p>Uses {@code Axis2Sender.sendBack()} — the correct method for sending a response
     * from within a gateway handler. {@code AxisEngine.send()} must NOT be used here as it
     * dispatches an outgoing request to the backend, not a response to the caller.
     */
    private boolean sendUnauthorized(org.apache.synapse.MessageContext synCtx,
                                     MessageContext axis2MC, String reason) {
        axis2MC.setProperty("HTTP_SC", 401);
        axis2MC.setProperty("NO_ENTITY_BODY", Boolean.TRUE);

        // Replace transport headers with a minimal response-only set
        Map<String, String> responseHeaders = new java.util.HashMap<>();
        responseHeaders.put("Content-Type", "application/json");
        axis2MC.setProperty(MessageContext.TRANSPORT_HEADERS, responseHeaders);

        synCtx.setProperty("RESPONSE", "true");
        synCtx.setResponse(true);
        synCtx.setTo(null);

        synCtx.setProperty(SynapseConstants.ERROR_CODE, 401);
        synCtx.setProperty(SynapseConstants.ERROR_MESSAGE, "Unauthorized: " + reason);
        synCtx.setProperty(SynapseConstants.ERROR_DETAIL, reason);

        Axis2Sender.sendBack(synCtx);
        return false;
    }
}

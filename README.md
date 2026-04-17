# CN Validation Handler

A custom WSO2 API Manager 4.x gateway handler that validates the client certificate CN (Common Name) forwarded by an load balancer via an HTTP header.

## Use Case

Validation is conditional: the handler checks a trust zone header injected by F5 and only enforces CN validation for the configured zone (e.g. internet-facing traffic). Internal traffic passes through untouched.

## How It Works

On each request the handler:

1. Checks the trust zone header — skips validation if the request is not from the expected zone
2. Reads the forwarded certificate from the configured header
3. Parses the PEM/base64 certificate (handles both URL-encoded and raw base64)
4. Extracts the CN from the Subject DN
5. Checks the CN against the configured allowed list — returns `401 Unauthorized` if not matched

On success, sets `VALIDATED_CLIENT_CN` on the message context for downstream use.

## Handler Properties

| Property | Default | Description |
|---|---|---|
| `certificateHeader` | `X-Client-Cert` | HTTP header carrying the forwarded client certificate |
| `trustZoneHeader` | `X-WSO2-Trust-Zone` | Header injected by F5 to identify the ingress zone |
| `trustZoneValue` | `internet` | Expected zone value that triggers CN validation |
| `allowedCns` | _(required)_ | Comma-separated list of permitted CN values |

## Build

Requires Java 11+ and Maven.

```bash
mvn clean package
```

Output: `target/cn-validation-handler.jar`

## Deployment

Copy the JAR to the APIM gateway dropins directory and restart:

```bash
cp target/cn-validation-handler.jar <APIM_HOME>/repository/components/dropins/
```

## Velocity Template Configuration

In `<APIM_HOME>/repository/resources/api_templates/velocity_template.xml`, add the handler conditionally based on API custom properties:

```xml
#if($apiObj.additionalProperties.get('cn_validation') == "true")
<handler xmlns="http://ws.apache.org/ns/synapse" class="com.example.gateway.CNValidationHandler">
    <property name="certificateHeader" value="$!apiObj.additionalProperties.get('certificate_header')"/>
    <property name="allowedCns"        value="$!apiObj.additionalProperties.get('allowed_cns')"/>
    <property name="trustZoneHeader"   value="X-WSO2-Trust-Zone"/>
    <property name="trustZoneValue"    value="internet"/>
</handler>
#end
```

Then set these custom properties on each API via Publisher:

| Property | Example Value |
|---|---|
| `cn_validation` | `true` |
| `certificate_header` | `X-Client-Cert` |
| `allowed_cns` | `ClientAppA,ClientAppB` |

## Debugging

Enable DEBUG logging for the handler in `<APIM_HOME>/repository/conf/log4j2.properties`:

```properties
logger.log-msg-handler.name = com.example.gateway.CNValidationHandler
logger.log-msg-handler.level = DEBUG
```

Also add `log-msg-handler` to the `loggers` list in the same file:

```properties
loggers = log-msg-handler, ...existing loggers...
```

## Testing

The handler reads the certificate as raw base64 (no PEM headers). Use `openssl` to generate test certs and strip the headers before sending.

**Scenario A — Internal traffic (no trust zone header) → expect 200**

Handler skips CN validation entirely when `X-WSO2-Trust-Zone` is absent.

```bash
curl -k https://localhost:8243/<api-context>/1.0.0 \
  -H "Authorization: Bearer <token>"
```

**Scenario B — Internet traffic with valid CN → expect 200**

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/test.key -out /tmp/test.crt \
  -days 1 -nodes -subj "/CN=TestClient/O=Test/C=NL"

CERT_B64=$(grep -v "BEGIN\|END" /tmp/test.crt | tr -d '\n')

curl -k https://localhost:8243/<api-context>/1.0.0 \
  -H "Authorization: Bearer <token>" \
  -H "X-WSO2-Trust-Zone: internet" \
  -H "X-Client-Cert: $CERT_B64"
```

> `TestClient` must be in the `allowed_cns` API property.

**Scenario C — Internet traffic with wrong CN → expect 401**

```bash
openssl req -x509 -newkey rsa:2048 -keyout /tmp/bad.key -out /tmp/bad.crt \
  -days 1 -nodes -subj "/CN=UnauthorizedClient/O=Test/C=NL"

BAD_B64=$(grep -v "BEGIN\|END" /tmp/bad.crt | tr -d '\n')

curl -k https://localhost:8243/<api-context>/1.0.0 \
  -H "Authorization: Bearer <token>" \
  -H "X-WSO2-Trust-Zone: internet" \
  -H "X-Client-Cert: $BAD_B64"
```



# CustomHandler-CNValidationHandler
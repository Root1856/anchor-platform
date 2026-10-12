# Proof of Concept

## Title
Public SEP server reads JSON request bodies of unlimited size into heap, allowing unauthenticated memory exhaustion of the Anchor Platform SEP API

(145 characters)

## Description

### Summary:
The Internet-facing SEP server of the Stellar Anchor Platform (release 4.9.0 and current `develop`) accepts request bodies of unlimited size on every JSON endpoint, including the two unauthenticated authentication endpoints. The `RequestBodySizeLimitFilter` introduced for ANCHOR-1313 protects only the internal Platform server; the SEP server has no equivalent filter and no servlet-container limit applies to JSON bodies.

* `platform/src/main/java/org/stellar/anchor/platform/component/platform/PlatformServerBeans.java` lines 71 to 87 register `RequestBodySizeLimitFilter` on `/*` for the Platform server only (`platform_server.max_request_body_size`, default 1 MiB).
* `platform/src/main/java/org/stellar/anchor/platform/SepServer.java` lines 24 to 29 component-scan only `controller.sep`, `component.sep` and `component.share`. `component/sep/SepBeans.java` registers the JWT filter and `component/share/RequestLoggerBeans.java` the request logger; no size limit exists anywhere under `platform/src/main` (no `server.tomcat.*` or `spring.servlet.*` size property is set).
* Spring Boot 3.2.4 with embedded Tomcat: Tomcat's 2 MiB `maxPostSize` applies only to `application/x-www-form-urlencoded` parameter parsing. `@RequestBody` JSON is read from the servlet input stream without limit and fully materialised by Gson (`spring.mvc.converters.preferred-json-mapper=gson`, `SepConfigManager.java` line 47) before any application validation runs.
* Unauthenticated endpoints reached this way: `POST /auth` (SEP-10, `Sep10Controller.java` lines 73 to 83; the 50 000 character check in `Sep10Service.parseChallenge` runs only after the whole body is already a Java `String`) and `POST /sep45/auth` (SEP-45, `Sep45Controller.java` lines 62 to 71, same pattern).
* Authenticated endpoints additionally persist the data: `POST /sep31/transactions` stores `fields.transaction` verbatim in a JSON column (`Sep31Service.java` line 237), `PATCH /sep6/transactions/{id}` stores the supplied values, `PUT /sep12/customer` and `POST /sep24/transactions/{deposit,withdraw}/interactive` read unbounded JSON maps.

A remote attacker streams a chunked JSON body with one very long string field. Every byte is appended to a `StringBuilder` inside `com.google.gson.stream.JsonReader.nextQuotedValue`, so a few tens of megabytes per connection are enough to exhaust a heap of several hundred megabytes when several connections run concurrently. This is the same defect class as ANCHOR-1313 and ANCHOR-1283, which were fixed on the Platform server, but on the server that is designed to be public.

### Steps To Reproduce:
Performed on a local build of 4.9.0 only (SEP server on port 8080, started with a 512 MiB heap to make the effect visible quickly). No public network was used.

1. Build and start the SEP server:
   ```
   ./gradlew :service-runner:bootJar -x test
   java -Xmx512m -jar service-runner/build/libs/anchor-platform-runner-4.9.0.jar --sep-server
   ```
2. Confirm the Platform server would reject a large body (reference behaviour): a `PATCH /transactions` on port 8085 with a 2 MB body returns `413 {"error":"The request body is too large."}`.
3. Send three concurrent chunked JSON bodies, each consisting of `{"transaction":"` followed by 400 000 000 bytes of the letter `A` and a closing `"}`, to the unauthenticated endpoint. `Content-Length` is omitted so that `Transfer-Encoding: chunked` is used, and the body is generated on the fly (for example from `/dev/zero` through `tr`), so the attacker needs no memory:
   ```
   POST /auth HTTP/1.1
   Host: localhost:8080
   Content-Type: application/json
   Transfer-Encoding: chunked

   {"transaction":"AAAA... (streamed) ..."}
   ```
4. Watch the SEP server log and probe liveness with `GET /sep24/info` and `GET /auth?account=...` from a second client.

### Results observed:
```
worker 3 -> HTTP 500, sent 36173664 bytes in 0.798235s
worker 2 -> HTTP 500, sent 36042600 bytes in 0.846107s
worker 1 -> HTTP 500, sent 69070728 bytes in 0.819311s
server log:
07:34:42.677 ERROR - o.s.a.u.Log - jakarta.servlet.ServletException: Handler dispatch failed: java.lang.OutOfMemoryError: Java heap space
Caused by: java.lang.OutOfMemoryError: Java heap space
	at java.base/java.util.Arrays.copyOf(Arrays.java:3537)
	at java.base/java.lang.AbstractStringBuilder.ensureCapacityInternal(AbstractStringBuilder.java:228)
	at java.base/java.lang.StringBuilder.append(StringBuilder.java:233)
	at com.google.gson.stream.JsonReader.nextQuotedValue(JsonReader.java:1173)
	at com.google.gson.stream.JsonReader.nextString(JsonReader.java:962)
	at org.springframework.http.converter.json.GsonHttpMessageConverter.readInternal(GsonHttpMessageConverter.java:92)
```
About 36 MB uploaded per connection was enough to exhaust the 512 MiB heap. Repeating the three streams continuously for 30 seconds produced 138 `OutOfMemoryError` entries in the log. For completeness: in this test Tomcat caught each error and the process stayed up; a loop of legitimate SEP-10 plus SEP-24 flows from the same machine completed 95 flows in 30 seconds during the attack versus 295 without it, with no hard failures. The demonstrated effect is therefore repeated heap exhaustion and heavy degradation from a trivial unauthenticated request, with the possibility of a full outage depending on heap sizing and on which other thread fails its allocation at the moment of exhaustion. The reference behaviour on the Platform server is an immediate `413` before any byte of the body is buffered.

### Confirmation from public sources:
* stellar/anchor-platform pull request 2030 ("[ANCHOR-1313]: Unauthenticated Denial of Service (OOM) via Unbounded Batch Size in Platform API PATCH /transactions"), merged into `develop` on 30 September 2026: introduces `platform_server.max_request_body_size` and states in its known-limitations section that "the limit applies to the Platform server only; the SEP server has no request body cap". This report demonstrates that the gap left open there is reachable without authentication on the public server.
* Spring Boot issue 41155 (spring-projects/spring-boot): maintainers confirm that the form post size property only applies to posted form content and has no effect on other request bodies; Tomcat's `maxPostSize` documentation likewise describes the limit as applying to form URL parameter parsing. A JSON body therefore needs an application-level cap, which is exactly what the Platform server got and the SEP server did not.
* stellar/anchor-platform `develop` branch, `platform/src/main/java/org/stellar/anchor/platform/SepServer.java` and `component/sep/SepBeans.java`, show no registration of `RequestBodySizeLimitFilter` for the SEP server.

### Suggested fix:
Register the existing `RequestBodySizeLimitFilter` in `SepBeans` with a `sep_server.max_request_body_size` setting (a few hundred kilobytes is ample for every SEP request), mirroring the ANCHOR-1313 change for the Platform server.

## Impact

### Summary:
Availability. An unauthenticated remote attacker can exhaust the heap of the public SEP server with a handful of cheap streamed requests (tens of megabytes per connection, no flooding, no paid transactions), causing repeated `OutOfMemoryError`s, failed requests and heavy degradation of SEP-10 and SEP-45 authentication and of all wallet-facing SEP-6, SEP-12, SEP-24, SEP-31 and SEP-38 endpoints for every customer of the anchor, with escalation to a full outage possible depending on heap sizing. Authenticated variants additionally let one user write unbounded blobs into the anchor's database and event stream. CVSS v3.1 base 5.3 to 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L or A:H).

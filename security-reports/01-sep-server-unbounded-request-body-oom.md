# Proof of Concept

## Title
Unauthenticated memory exhaustion (DoS) via unbounded JSON request body on the public SEP server (anchor-platform ≤ 4.9.0)

## Description

### Summary:
The public, Internet-facing **SEP server** of the Stellar Anchor Platform accepts request bodies of unlimited size on every JSON endpoint. The `RequestBodySizeLimitFilter` that was introduced to fix ANCHOR-1313 ("Unauthenticated Denial of Service (OOM) via unbounded batch size") is registered **only on the Platform (internal) server**; the SEP server has no equivalent filter and no Tomcat/Spring body-size properties.

* `platform/src/main/java/org/stellar/anchor/platform/component/platform/PlatformServerBeans.java:71-84` registers `RequestBodySizeLimitFilter` on `/*` for the Platform server only (`platform_server.max_request_body_size`, default 1 MiB).
* `platform/src/main/java/org/stellar/anchor/platform/SepServer.java:24-29` component-scans only `controller.sep`, `component.sep`, `component.share`. `component/sep/SepBeans.java` registers just the `WebAuthJwtFilter`; `component/share/RequestLoggerBeans.java` registers the request logger. No size limit is configured anywhere under `platform/src/main` (`grep -rn "max-http\|maxPostSize\|max-swallow" platform/src/main` is empty).
* Spring Boot 3.2.4 + embedded Tomcat: Tomcat's 2 MiB `maxPostSize` only bounds `application/x-www-form-urlencoded` parameter parsing. `@RequestBody` JSON is read through the servlet input stream with no limit and is materialised in full by Gson (`spring.mvc.converters.preferred-json-mapper=gson`, `SepConfigManager.java:47`) before any business validation runs.

Unauthenticated JSON endpoints reached this way:

* `POST /auth` (SEP-10, `Sep10Controller.java:73-83`) — `ValidationRequest.transaction` is a String; the 50 000-char check in `Sep10Service.parseChallenge` runs only **after** the full body has been buffered.
* `POST /sep45/auth` (SEP-45, `Sep45Controller.java:62-71`) — same pattern, `authorization_entries` String, 50 000-char check after full parse.

Authenticated JSON endpoints (any wallet user with a valid SEP-10 token, which is free to obtain) additionally **persist** the unbounded data:

* `POST /sep31/transactions` — `fields.transaction` is stored verbatim as a JSON column (`Sep31Service.java:237`, `JdbcSep31Transaction`), no key/value size limit.
* `PATCH /sep6/transactions/{id}` — values of `required_info_updates` are stored verbatim.
* `PUT /sep12/customer` (JSON) and `POST /sep24/transactions/{deposit,withdraw}/interactive` (JSON `HashMap<String,String>`).

A single attacker can therefore make the JVM allocate an arbitrarily large `String`/`StringBuilder` per connection. With the default container heap (the Docker image runs with no `-Xmx` override) a handful of concurrent connections streaming a few hundred MB each is enough to trigger `java.lang.OutOfMemoryError` in the SEP server, taking SEP-10/SEP-45 authentication and every wallet-facing SEP endpoint offline until the process is restarted. This is the same bug class as ANCHOR-1313/ANCHOR-1283 which were accepted for the Platform server, but on the server that is *meant* to be public.

### Steps To Reproduce:
All steps are against a **local** instance (never testnet/pubnet).

  1. Start the Anchor Platform locally with SEP-10 enabled, e.g. `cd quick-run && docker compose up -d` (SEP server on `http://localhost:8080`). For a clear demonstration cap the heap, e.g. `JAVA_OPTS=-Xmx512m`.
  2. Confirm the Platform server rejects large bodies while the SEP server does not:
     ```
     # Platform API (port 8085) – protected
     head -c 2000000 /dev/zero | tr '\0' 'A' | curl -s -o - -w '\n%{http_code}\n' -X PATCH http://localhost:8085/transactions \
          -H 'Content-Type: application/json' --data-binary @-
     # -> {"error":"The request body is too large."}  413
     ```
  3. Stream an oversized JSON body to the unauthenticated SEP-10 endpoint. `Content-Length` is deliberately omitted (chunked transfer) so no length pre-check can apply, and the body is generated on the fly so the attacker needs no memory:
     ```
     ( printf '{"transaction":"'; head -c 800000000 /dev/zero | tr '\0' 'A'; printf '"}' ) | \
       curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8080/auth \
            -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' --data-binary @-
     ```
     Run 3–4 of these in parallel (`for i in 1 2 3 4; do ( ... ) & done`).
  4. Observe the SEP server log: `java.lang.OutOfMemoryError: Java heap space` (from `com.google.gson.stream.JsonReader.nextQuotedValue` / `StringBuilder.append`), followed by failed or hanging requests to `GET /auth` and `GET /sep24/info` from a separate client. On a JVM without a heap cap the container is OOM-killed by the kernel instead.
  5. Expected behaviour (what the Platform server does): an immediate `413` with `{"error":"The request body is too large."}` before the body is read into memory.

### Supporting Material:
  * `platform/src/main/java/org/stellar/anchor/platform/component/platform/PlatformServerBeans.java:71-84` (filter registered for Platform server only)
  * `platform/src/main/java/org/stellar/anchor/platform/SepServer.java:24-29` (SEP server component scan; no body-limit bean in any scanned package)
  * `platform/src/main/java/org/stellar/anchor/platform/controller/sep/Sep10Controller.java:73-83`, `Sep45Controller.java:62-71` (unauthenticated `@RequestBody` endpoints)
  * `core/src/main/java/org/stellar/anchor/sep10/Sep10Service.java` `parseChallenge` – size check happens after the full body is already in memory.
  * Fix reference: register the existing `RequestBodySizeLimitFilter` in `SepBeans` with a `sep_server.max_request_body_size` setting, exactly as done for `platform_server` in ANCHOR-1313.

## Impact

### Summary:
Availability. An unauthenticated remote attacker can exhaust the heap of the public SEP server with a few streamed requests (no flooding, no paid transactions), crashing or wedging SEP-10/SEP-45 authentication and all wallet-facing SEP-6/12/24/31/38 endpoints for every customer of the anchor until the service is restarted. Authenticated variants additionally let one user write unbounded blobs into the anchor's database and event stream (storage exhaustion, downstream business-server impact). CVSS v3.1: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).

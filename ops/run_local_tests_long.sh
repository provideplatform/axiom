#!/bin/bash

set -e
echo "" > coverage.txt

if [[ -z "${DATABASE_NAME}" ]]; then
  export DATABASE_NAME=nchain_dev
fi

if [[ -z "${DATABASE_USER}" ]]; then
  export DATABASE_USER=nchain
fi

if [[ -z "${DATABASE_PASSWORD}" ]]; then
  export DATABASE_PASSWORD=nchain
fi

if [[ -z "${NATS_SERVER_PORT}" ]]; then
  export NATS_SERVER_PORT=4221
fi

if [[ -z "${NATS_STREAMING_SERVER_PORT}" ]]; then
  export NATS_STREAMING_SERVER_PORT=4222
fi

if [[ -z "${REDIS_SERVER_PORT}" ]]; then
  export REDIS_SERVER_PORT=6379
fi

if [[ -z "${RACE}" ]]; then
  export RACE=true
fi

if [[ -z "${TAGS}" ]]; then
  export TAGS=unit
fi

export IDENT_API_HOST=localhost:8081
export IDENT_API_PATH=api/v1
export IDENT_API_SCHEME=http

export NCHAIN_API_HOST=localhost:8082
export NCHAIN_API_PATH=api/v1
export NCHAIN_API_SCHEME=http

export PRIVACY_API_HOST=localhost:8083
export PRIVACY_API_PATH=api/v1
export PRIVACY_API_SCHEME=http

export VAULT_API_HOST=localhost:8085
export VAULT_API_PATH=api/v1
export VAULT_API_SCHEME=http

export VAULT_SEAL_UNSEAL_KEY='traffic charge swing glimpse will citizen push mutual embrace volcano siege baseline-proxyify gossip battle casual exit enrich unlock muscle vast female initial please day'
export VAULT_REFRESH_TOKEN=eyJhbGciOiJSUzI1NiIsImtpZCI6IjEwOjJlOmQ5OmUxOmI4OmEyOjM0OjM3Ojk5OjNhOjI0OmZjOmFhOmQxOmM4OjU5IiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL3Byb3ZpZGUuc2VydmljZXMvYXBpL3YxIiwiaWF0IjoxNjA1NzkxMjQ4LCJpc3MiOiJodHRwczovL2lkZW50LnByb3ZpZGUuc2VydmljZXMiLCJqdGkiOiI5YjUxNGIxNS01NTdlLTRhYWQtYTcwOC0wMTcwZTAwZWE1ZmIiLCJuYXRzIjp7InBlcm1pc3Npb25zIjp7InN1YnNjcmliZSI6eyJhbGxvdyI6WyJhcHBsaWNhdGlvbi4zNjAxNTdmOC1kNWExLTQ0NDAtOTE4Yi1mNjhiYjM5YzBkODAiLCJ1c2VyLjIzY2MwN2UwLTM4NTEtNDBkZC1iNjc1LWRmNzY4MDY3MmY3ZCIsIm5ldHdvcmsuKi5jb25uZWN0b3IuKiIsIm5ldHdvcmsuKi5zdGF0dXMiLCJwbGF0Zm9ybS5cdTAwM2UiXX19fSwicHJ2ZCI6eyJhcHBsaWNhdGlvbl9pZCI6IjM2MDE1N2Y4LWQ1YTEtNDQ0MC05MThiLWY2OGJiMzljMGQ4MCIsImV4dGVuZGVkIjp7InBlcm1pc3Npb25zIjp7IioiOjUxMH19LCJwZXJtaXNzaW9ucyI6NTEwLCJ1c2VyX2lkIjoiMjNjYzA3ZTAtMzg1MS00MGRkLWI2NzUtZGY3NjgwNjcyZjdkIn0sInN1YiI6ImFwcGxpY2F0aW9uOjM2MDE1N2Y4LWQ1YTEtNDQ0MC05MThiLWY2OGJiMzljMGQ4MCJ9.SUh84MKBNstdu3KFu1zEAQq03xbPw1D0lLXeogz1HfBJy77bIGf7HLvCuc6bjkh0xj3cEuEus1dC1Dj3BvlZoSXsvz_biTzSapkXzJjpkwOL6qkYDmqTPZvXwqmk-mUNrHTPkqdiIJL7xA46tzHW3E_hjSA9HjEk1kXjPdJQ6_ifkgWNoAaSD--kudIrhZ7vLnfy0H1JEAOsXzSAMoc5_pNG2n79m0ywvb_4l9BqdsHW8N3xSQOFjcp9gD_tqo6ffug3pkpoy-RSguM_OaMR2lj_CHhYxAt0phtjUceDD3K1h5iZ38kSl7izhOdULMmGBhVpBMoSy6_R6ZzpCL3pj8FcReX9RXR5oYpm8PDtlmWqblQzjwY00-uYLfOX0_iS4MGfEsjadZPfTmJLcOTYC7H4PL9ZRu_XtMDUrGBQQz5b_ad2ZzMXbBNeU6vbxVKDG8VFKWOHAemqHTcvuOAsOCLIqOu-eJpZHlXbx-FXPTYledd-GBDe7IjaC9ll_JK3utCOnCq0qUs6lnXIrQ_Sp1LcTKJJ7aY5f9TxeoAuL-ghDbQ3Xkw6huKyPCz2evOwVLwrB9ZRMlQXgmTnB1OeQvWii1WbmkyV1Zhbz_RPB8ckK7_mFxuPvsXK8wTFiWFmj96sRX470kV-ooSfM5CzKZhSLqgyyaUNC0VaCPq0uuE

echo waiting for vault to be ready
timeout 30 bash -c 'while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' '${VAULT_API_SCHEME}"://"${VAULT_API_HOST}'/status)" != "204" ]]; do sleep 5; done' || false
echo vault ready

echo waiting for baseline-proxy to be ready
timeout 30 bash -c 'while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' '${IDENT_API_SCHEME}"://"${IDENT_API_HOST}'/status)" != "200" ]]; do sleep 5; done' || false
echo baseline-proxy ready

echo waiting for nchain to be ready
timeout 30 bash -c 'while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' '${NCHAIN_API_SCHEME}"://"${NCHAIN_API_HOST}'/status)" != "204" ]]; do sleep 5; done' || false
echo nchain ready

echo waiting for privacy to be ready
timeout 30 bash -c 'while [[ "$(curl -s -o /dev/null -w ''%{http_code}'' '${PRIVACY_API_SCHEME}"://"${PRIVACY_API_HOST}'/status)" != "204" ]]; do sleep 5; done' || false
echo privacy ready

export NATS_TOKEN=testtoken
export NATS_URL=nats://localhost:${NATS_SERVER_PORT}
export NATS_STREAMING_URL=nats://localhost:${NATS_STREAMING_SERVER_PORT}
export NATS_CLUSTER_ID=provide
export DATABASE_HOST=localhost
export LOG_LEVEL=DEBUG

go test "./test/..." -v \
                    -race \
                    -timeout 1800s \
                    -parallel 1 \
                    -tags="$TAGS"
 
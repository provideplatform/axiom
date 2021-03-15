#!/bin/bash

IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http ./ops/run_api.sh &
IDENT_API_HOST=localhost:8081 IDENT_API_SCHEME=http ./ops/run_consumer.sh &

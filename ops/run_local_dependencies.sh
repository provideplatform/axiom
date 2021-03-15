#!/bin/bash

if hash psql 2>/dev/null
then
    echo 'Using' `psql --version`
else
    echo 'Installing postgresql'
    sudo apt-get update
    sudo apt-get -y install postgresql
fi

if hash gnatsd 2>/dev/null
then
    echo 'Using' `gnatsd --version`
else
    echo 'Installing NATS server'
    go get github.com/nats-io/gnatsd
fi

if hash nats-streaming-server 2>/dev/null
then
    echo 'Using' `nats-streaming-server --version`
else
    echo 'Installing NATS streaming server'
    go get github.com/nats-io/nats-streaming-server
fi

if [[ -z "${NATS_SERVER_PORT}" ]]; then
  NATS_SERVER_PORT=4221
fi

if [[ -z "${DATABASE_PORT}" ]]; then
  DATABASE_PORT=5432
fi

if [[ -z "${NATS_STREAMING_SERVER_PORT}" ]]; then
  NATS_STREAMING_SERVER_PORT=4222
fi

gnatsd -auth testtoken -p ${NATS_SERVER_PORT} > /dev/null 2>&1 &
nats-streaming-server -cid provide -auth testtoken -p ${NATS_STREAMING_SERVER_PORT} > /dev/null 2>&1 &
pg_ctl -D /usr/local/var/postgres -p ${DATABASE_PORT} start > /dev/null 2>&1 &

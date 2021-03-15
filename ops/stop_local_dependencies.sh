#!/bin/bash

pkill gnatsd
pkill nats-streaming-server
pg_ctl -D /usr/local/var/postgres stop -s -m fast

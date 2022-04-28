# Baseline Protocol Instance (BPI) API & Systems Middleware

Production-grade, standards-compliant API and middleware implementation of the Baseline Protocol with support for various systems.

## Usage

See the [baseline API Reference](https://docs.provide.services/api/rest-api-v1/baseline).

## Run your own BPI with Docker

Requires [Docker](https://www.docker.com/get-started)

```shell
/ops/docker-compose up
```

## Build and run your own BPI from source

Requires [GNU Make](https://www.gnu.org/software/make), [Go](https://go.dev/doc/install), [Postgres](https://www.postgresql.org/download), [Redis](https://redis.io/docs/getting-started/installation)

```shell
make run_local
```

## Executables

The project comes with several wrappers/executables found in the `cmd`
directory.

|  Command   | Description          |
|:----------:|----------------------|
| **`api`**  | Runs the API server. |
| `consumer` | Runs a consumer.     |
| `migrate`  | Runs migrations.     |

<div align="center">
<h1>LightHouse</h1>
</div>

Self-hosted push notification server implementing the Skyglow Protocol v2 (SGP/2). Pairs with the [Skyglow Notifications Client](https://github.com/ObscureMosquito/Skyglow-Notifications-Client) to deliver notifications over a persistent TLS connection, replacing Apple Push Notification Service on legacy devices.

## Requirements

- Java 21+
- PostgreSQL
- OpenSSL (for certificate generation)

## Setup

#### 1. Generate the server certificate:

```bash
./generate-certificate.sh server --name your.domain.com
```

This creates `cert.pem` and `key.pem` in the current directory.

> [!TIP]
> To restrict device registration to authorized operators, generate a registration CA and issue client certificates:
>
> ```bash
> ./generate-certificate.sh ca
> ./generate-certificate.sh client --name alice
> ```

#### 2. Configure environment variables:

| Variable             | Description                          | Default           |
| -------------------- | ------------------------------------ | ----------------- |
| `SGP_CERT_PATH`      | TLS certificate PEM                  | required          |
| `SGP_KEY_PATH`       | TLS key PEM (unencrypted PKCS#8)     | required          |
| `SGP_DB_URL`         | PostgreSQL JDBC URL                  | required          |
| `SGP_DB_USER`        | Database user                        | required          |
| `SGP_DB_PASS`        | Database password                    | required          |
| `SGP_SERVER_ADDRESS` | Public domain for this server        | required          |
| `SGP_TCP_PORT`       | SGP/2 listener port                  | `7373`            |
| `SGP_HTTP_PORT`      | HTTP API port                        | `7878`            |
| `SGP_HTTP_BIND`      | HTTP bind address                    | `127.0.0.1`       |
| `SGP_TLS_MIN`        | Minimum TLS version (`1.2` or `1.3`) | `1.3`             |
| `SGP_REG_CA_PATH`    | Registration CA PEM (optional)       | open registration |

#### 3. Build:

```bash
mvn package -DskipTests
```

#### 4. Run:

```bash
java -jar target/LightHouse-1.0-SNAPSHOT.jar
```

## HTTP API

| Method | Path                   | Description                                        |
| ------ | ---------------------- | -------------------------------------------------- |
| `POST` | `/send`                | Send a notification to a device by routing key     |
| `GET`  | `/health`              | Server status and connected device count           |
| `GET`  | `/snd/server_cert.pem` | Download the server certificate for client pinning |

## Documentation

Protocol Documentation can be found [here](https://cydia.skyglow.es/tweaks/Notifications/Documentation/protocol.html).

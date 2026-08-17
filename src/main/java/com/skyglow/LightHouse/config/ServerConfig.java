package com.skyglow.LightHouse.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 *   SGP_TCP_PORT        SGP/2 listener port                    default 7373
 *   SGP_HTTP_PORT       HTTP API port                          default 7878
 *   SGP_HTTP_BIND       HTTP bind address                      default 127.0.0.1
 *   SGP_CERT_PATH       TLS certificate PEM                    required
 *   SGP_KEY_PATH        TLS key PEM, unencrypted PKCS#8        required
 *   SGP_DB_URL          PostgreSQL JDBC URL                    required
 *   SGP_DB_USER         database user                          required
 *   SGP_DB_PASS         database password                      required
 *   SGP_SERVER_ADDRESS  this server's public domain            required
 *   SGP_TLS_MIN         1.2 or 1.3                             default 1.3
 *   SGP_REG_CA_PATH     registration CA PEM                    optional
 */
public record ServerConfig(
        int     tcpPort,
        int     httpPort,
        String  httpBind,
        String  certPath,
        String  keyPath,
        String  dbUrl,
        String  dbUser,
        String  dbPass,
        String  serverAddress,
        String  regCaPath,
        boolean allowTls12
) {

    private static final Logger log = LoggerFactory.getLogger(ServerConfig.class);

    public boolean requireRegCert() { return regCaPath != null; }

    public String[] tlsProtocols() {
        return allowTls12 ? new String[]{"TLSv1.2", "TLSv1.3"} : new String[]{"TLSv1.3"};
    }

    /** Exits the process on a fatal misconfiguration, warns on the recoverable ones. */
    public static ServerConfig fromEnv() {
        String tlsMin = str("SGP_TLS_MIN", "1.3");
        boolean allowTls12 = switch (tlsMin) {
            case "1.3" -> false;
            case "1.2" -> true;
            default -> {
                fatal("SGP_TLS_MIN must be 1.2 or 1.3, got: " + tlsMin);
                yield false;
            }
        };
        if (allowTls12) {
            log.warn("SGP_TLS_MIN=1.2, client certificates are sent in cleartext on 1.2 handshakes");
        }

        String serverAddress = require("SGP_SERVER_ADDRESS");
        validateServerAddress(serverAddress);

        String regCaPath = str("SGP_REG_CA_PATH", null);
        if (regCaPath == null) {
            log.warn("SGP_REG_CA_PATH not set, device registration is OPEN to anyone");
        }

        return new ServerConfig(
                integer("SGP_TCP_PORT", 7373),
                integer("SGP_HTTP_PORT", 7878),
                str("SGP_HTTP_BIND", "127.0.0.1"),
                require("SGP_CERT_PATH"),
                require("SGP_KEY_PATH"),
                require("SGP_DB_URL"),
                require("SGP_DB_USER"),
                require("SGP_DB_PASS"),
                serverAddress,
                regCaPath,
                allowTls12);
    }

    private static void validateServerAddress(String address) {
        if (address.getBytes(StandardCharsets.UTF_8).length > 16) {
            log.warn("SGP_SERVER_ADDRESS '{}' exceeds 16 bytes, client-side token generation WILL fail", address);
        }
        if (!address.matches("[A-Za-z0-9._@-]+")) {
            log.warn("SGP_SERVER_ADDRESS '{}' has characters outside [A-Za-z0-9._@-], clients WILL reject it", address);
        }
    }

    private static String require(String name) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) fatal("Required environment variable not set: " + name);
        return v;
    }

    private static String str(String name, String defaultValue) {
        String v = System.getenv(name);
        return (v == null || v.isBlank()) ? defaultValue : v.trim();
    }

    private static int integer(String name, int defaultValue) {
        String v = System.getenv(name);
        if (v == null || v.isBlank()) return defaultValue;
        try {
            return Integer.parseInt(v.trim());
        } catch (NumberFormatException e) {
            log.warn("Invalid integer for {}: {}, using default {}", name, v, defaultValue);
            return defaultValue;
        }
    }

    private static void fatal(String message) {
        System.err.println("FATAL: " + message);
        System.exit(1);
    }
}

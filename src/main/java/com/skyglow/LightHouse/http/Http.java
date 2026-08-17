package com.skyglow.LightHouse.http;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/** Request and response stuff shared by every {@link HttpModule}. */
public final class Http {

    /** shared mapper */
    public static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private Http() {}

    public static void text(HttpExchange ex, int status, String body) throws IOException {
        bytes(ex, status, "text/plain; charset=utf-8", body.getBytes(StandardCharsets.UTF_8));
    }

    public static void json(HttpExchange ex, int status, JsonNode body) throws IOException {
        bytes(ex, status, "application/json", MAPPER.writeValueAsBytes(body));
    }

    public static void jsonError(HttpExchange ex, int status, String message) throws IOException {
        json(ex, status, MAPPER.createObjectNode().put("error", message));
    }

    public static void bytes(HttpExchange ex, int status, String contentType, byte[] body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", contentType);
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(body); }
    }

    /** returns nil when the body exceeds {@code maxBytes}. */
    public static String body(HttpExchange ex, int maxBytes) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            byte[] buf = is.readNBytes(maxBytes + 1);
            return buf.length > maxBytes ? null : new String(buf, StandardCharsets.UTF_8);
        }
    }

    /** returns the decoded value of one query parameter, or nil when absent. */
    public static String query(HttpExchange ex, String key) {
        String q = ex.getRequestURI().getRawQuery();
        if (q == null) return null;
        for (String pair : q.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq >= 0 ? pair.substring(0, eq) : pair;
            if (k.equals(key)) {
                return URLDecoder.decode(eq >= 0 ? pair.substring(eq + 1) : "", StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /** The real client address behind the reverse proxy, else the socket peer. */
    public static String clientIp(HttpExchange ex) {
        String xff = ex.getRequestHeaders().getFirst("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return ex.getRemoteAddress().getAddress().getHostAddress();
    }

    public static boolean isLoopback(HttpExchange ex) {
        return ex.getRemoteAddress().getAddress().isLoopbackAddress();
    }
}

package com.skyglow.LightHouse.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.skyglow.LightHouse.SGPProtocol;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.db.Database.NotificationToken;
import com.skyglow.LightHouse.notify.NotificationService;
import com.skyglow.LightHouse.router.Router;
import com.sun.net.httpserver.HttpExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;


public final class PublicApiModule implements HttpModule {

    private static final Logger log = LoggerFactory.getLogger(PublicApiModule.class);
    
    private static final int MAX_BODY_BYTES = 64 * 1024;
    private static final int MAX_HOPS       = 10;
    private static final int  SEND_MISS_LIMIT     = 20;
    private static final long SEND_MISS_WINDOW_MS = 60_000;

    private final RateLimiter sendMisses = new RateLimiter(SEND_MISS_LIMIT, SEND_MISS_WINDOW_MS);

    private Database            db;
    private Router              router;
    private NotificationService notifications;
    private String              certPath;

    @Override
    public String name() { return "public-api"; }

    @Override
    public void register(RouteRegistry routes, ModuleContext ctx) {
        this.db            = ctx.db();
        this.router        = ctx.router();
        this.notifications = ctx.notifications();
        this.certPath      = ctx.config().certPath();

        routes.get("/health", this::health);
        routes.post("/send", this::send);
        routes.get("/snd/server_cert.pem", this::serverCert);
    }

    private void health(HttpExchange ex) throws IOException {
        Http.json(ex, 200, Http.MAPPER.createObjectNode()
                .put("status", "ok")
                .put("connections", router.connectedCount()));
    }

    /** for prefs registration */
    private void serverCert(HttpExchange ex) throws IOException {
        byte[] pem;
        try {
            pem = Files.readAllBytes(Path.of(certPath));
        } catch (IOException e) {
            log.error("Could not read server certificate at {}: {}", certPath, e.getMessage());
            Http.text(ex, 500, "Certificate unavailable");
            return;
        }
        Http.bytes(ex, 200, "application/x-pem-file", pem);
    }

    /** A muted routing key is accepted with 202 rather than rejected */
    private void send(HttpExchange ex) throws IOException {
        String clientIp = Http.clientIp(ex);
        if (sendMisses.isLimited(clientIp)) { Http.text(ex, 429, "Too Many Requests"); return; }

        String body = Http.body(ex, MAX_BODY_BYTES);
        if (body == null) { Http.text(ex, 413, "Payload Too Large"); return; }

        SendRequest req = parse(body);
        if (req == null) { Http.text(ex, 400, "Bad Request"); return; }
        if (req.totalHops() > MAX_HOPS) { Http.text(ex, 400, "Hop limit exceeded"); return; }

        try {
            Optional<NotificationToken> token = db.getToken(req.routingKey());
            if (token.isEmpty()) {
                sendMisses.record(clientIp);
                Http.text(ex, 404, "Routing key not found");
                return;
            }

            if (token.get().muted()) {
                Http.text(ex, 202, "Accepted (suppressed: muted)");
                return;
            }

            int max = NotificationService.maxPayloadBytes(req.encrypted());
            if (req.payload().length > max) {
                Http.text(ex, 413, "Payload Too Large: max " + max + " bytes");
                return;
            }

            notifications.dispatch(new NotificationService.Message(
                    token.get().deviceAddress(), req.routingKey(), req.payload(), req.iv(),
                    req.encrypted(), req.contentType(), req.expiresAt(),
                    req.priority(), req.collapseKey(), req.store()));

            Http.text(ex, 202, "Accepted");

        } catch (SQLException e) {
            log.error("DB error on /send: {}", e.getMessage(), e);
            Http.text(ex, 500, "Internal Server Error");
        }
    }

    private record SendRequest(
            byte[]  routingKey,
            boolean encrypted,
            byte[]  payload,
            byte[]  iv,
            byte    contentType,
            long    expiresAt,
            byte    priority,
            byte[]  collapseKey,
            int     totalHops,
            boolean store
    ) {}

    /** Parses and validates a /send body, returning null on anything malformed */
    private static SendRequest parse(String body) {
        try {
            JsonNode json = Http.MAPPER.readTree(body);
            if (json == null || !json.isObject()) return null;

            byte[] routingKey = HexFormat.of().parseHex(json.path("routing_key").asText(""));
            if (routingKey.length != SGPProtocol.ROUTING_KEY_LEN) return null;

            long expiresAt = json.path("expires_at").asLong(0);
            if (expiresAt != 0 && expiresAt <= Instant.now().getEpochSecond()) return null;

            int rawPriority = json.path("priority").asInt(json.path("is_critical").asBoolean(false)
                    ? SGPProtocol.PRIORITY_CRITICAL : SGPProtocol.PRIORITY_NORMAL);
            byte priority = (byte) Math.max(SGPProtocol.PRIORITY_NORMAL,
                    Math.min(SGPProtocol.PRIORITY_CRITICAL, rawPriority));

            byte[] collapseKey = null;
            String collapseB64 = json.path("collapse_key").asText("");
            if (!collapseB64.isEmpty()) {
                collapseKey = Base64.getDecoder().decode(collapseB64);
                if (collapseKey.length != SGPProtocol.COLLAPSE_KEY_LEN) return null;
            }

            boolean encrypted = json.path("is_encrypted").asBoolean(false);
            byte[] payload;
            byte[] iv = null;
            byte contentType;

            if (encrypted) {
                JsonNode ciphertext = json.path("ciphertext");
                JsonNode ivNode     = json.path("iv");
                if (!ciphertext.isTextual() || !ivNode.isTextual()) return null;
                payload = Base64.getDecoder().decode(ciphertext.asText());
                iv      = Base64.getDecoder().decode(ivNode.asText());
                if (payload.length == 0 || iv.length != SGPProtocol.GCM_IV_LEN) return null;
                int ct = json.path("content_type").asInt(SGPProtocol.CT_TLV);
                if (ct < SGPProtocol.CT_TLV || ct > SGPProtocol.CT_TLVSTRUCT) return null;
                contentType = (byte) ct;
            } else {
                JsonNode data = json.path("data");
                if (!data.isObject()) return null;
                payload     = SGPProtocol.encodeStructuredTlv(Http.MAPPER.convertValue(data, Object.class));
                contentType = SGPProtocol.CT_TLVSTRUCT;
            }

            return new SendRequest(routingKey, encrypted, payload, iv, contentType, expiresAt,
                    priority, collapseKey, json.path("total_hops").asInt(0),
                    json.path("store").asBoolean(true));

        } catch (Exception e) {
            return null;
        }
    }
}

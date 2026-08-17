package com.skyglow.LightHouse.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Core persistence for registered devices, their routing-key bindings, and the
 * offline message queue. Optional modules take the pool from
 * {@link #dataSource()} and own their own tables.
 */
public final class Database {

    private static final Logger log = LoggerFactory.getLogger(Database.class);

    private final HikariDataSource pool;

    public Database(String jdbcUrl, String user, String password) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(jdbcUrl);
        cfg.setUsername(user);
        cfg.setPassword(password);
        cfg.setMaximumPoolSize(20);
        cfg.setMinimumIdle(4);
        cfg.setConnectionTimeout(5_000);
        cfg.setIdleTimeout(300_000);
        cfg.setMaxLifetime(1_800_000);
        pool = new HikariDataSource(cfg);
        log.info("Database pool initialised: {}", jdbcUrl);
    }

    public DataSource dataSource() { return pool; }

    public void close() { pool.close(); }

    /** Creates the core tables and indexes if they do not already exist */
    public void initSchema() throws SQLException {
        try (Connection c = pool.getConnection(); Statement s = c.createStatement()) {
            s.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_address      VARCHAR(255) NOT NULL PRIMARY KEY,
                    pub_key             BYTEA        NOT NULL,
                    device_seq_counter  BIGINT       NOT NULL DEFAULT 0,
                    reg_cert_subject    VARCHAR(255)
                )
                """);
            s.execute("ALTER TABLE devices ADD COLUMN IF NOT EXISTS reg_cert_subject VARCHAR(255)");
            s.execute("""
                CREATE TABLE IF NOT EXISTS notification_tokens (
                    routing_token   BYTEA        NOT NULL PRIMARY KEY,
                    device_address  VARCHAR(255) NOT NULL,
                    bundle_id       VARCHAR(255) NOT NULL,
                    muted           BOOLEAN      NOT NULL DEFAULT FALSE,
                    issued_at       TIMESTAMP    NOT NULL DEFAULT NOW()
                )
                """);
            s.execute("""
                CREATE TABLE IF NOT EXISTS queued_messages (
                    message_id     BYTEA        NOT NULL PRIMARY KEY,
                    created_at     TIMESTAMP    NOT NULL,
                    expires_at     BIGINT       NOT NULL DEFAULT 0,
                    device_seq     BIGINT       NOT NULL,
                    priority       SMALLINT     NOT NULL DEFAULT 0,
                    collapse_key   BYTEA,
                    is_encrypted   BOOLEAN      NOT NULL,
                    data           BYTEA,
                    content_type   SMALLINT     NOT NULL DEFAULT 0,
                    ciphertext     BYTEA,
                    iv             BYTEA,
                    device_address VARCHAR(255) NOT NULL,
                    routing_key    BYTEA        NOT NULL
                )
                """);
            s.execute("CREATE INDEX IF NOT EXISTS idx_queued_expires_at ON queued_messages (expires_at) WHERE expires_at > 0");
            s.execute("CREATE INDEX IF NOT EXISTS idx_tokens_device ON notification_tokens (device_address)");
            s.execute("DROP INDEX IF EXISTS idx_queued_device");
            s.execute("CREATE INDEX IF NOT EXISTS idx_queued_device_seq ON queued_messages (device_address, device_seq)");
            s.execute("CREATE INDEX IF NOT EXISTS idx_queued_routing ON queued_messages (routing_key)");
            log.info("Schema initialised");
        }
    }

    public Optional<Device> getDevice(String address) throws SQLException {
        final String sql = "SELECT device_address, pub_key FROM devices WHERE device_address = ?";
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, address);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(new Device(rs.getString("device_address"), decodePublicKey(rs.getBytes("pub_key"))));
            }
        }
    }

    /** {@code certSubject} is the registration certificate's DN, or null when the gate was off. */
    public void createDevice(String address, RSAPublicKey pubKey, String certSubject) throws SQLException {
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(
                "INSERT INTO devices (device_address, pub_key, reg_cert_subject) VALUES (?, ?, ?)")) {
            ps.setString(1, address); ps.setBytes(2, pubKey.getEncoded()); ps.setString(3, certSubject);
            ps.executeUpdate();
        }
    }

    /** atomically increments and returns the device's next sequence number. */
    public long nextDeviceSeq(String address) throws SQLException {
        final String sql = "UPDATE devices SET device_seq_counter = device_seq_counter + 1 " +
                           "WHERE device_address = ? RETURNING device_seq_counter";
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, address);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) throw new SQLException("Device not found: " + address);
                return rs.getLong(1);
            }
        }
    }

    public Optional<NotificationToken> getToken(byte[] routingKey) throws SQLException {
        final String sql = "SELECT routing_token, device_address, bundle_id, muted, issued_at " +
                           "FROM notification_tokens WHERE routing_token = ?";
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setBytes(1, routingKey);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(new NotificationToken(
                        rs.getBytes("routing_token"), rs.getString("device_address"),
                        rs.getString("bundle_id"), rs.getBoolean("muted"),
                        rs.getTimestamp("issued_at").toInstant()));
            }
        }
    }

    /** any routing key bound to the device, optionally narrowed to one bundle. */
    public Optional<byte[]> getRoutingKeyForDevice(String deviceAddress, String bundleId) throws SQLException {
        boolean hasBundle = bundleId != null && !bundleId.isBlank();
        final String sql = "SELECT routing_token FROM notification_tokens WHERE device_address = ?" +
                (hasBundle ? " AND bundle_id = ?" : "") + " LIMIT 1";
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, deviceAddress);
            if (hasBundle) ps.setString(2, bundleId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) return Optional.empty();
                return Optional.of(rs.getBytes("routing_token"));
            }
        }
    }

    public List<String> getBundlesForDevice(String deviceAddress) throws SQLException {
        final String sql = "SELECT DISTINCT bundle_id FROM notification_tokens WHERE device_address = ?";
        List<String> bundles = new ArrayList<>();
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, deviceAddress);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) bundles.add(rs.getString("bundle_id"));
            }
        }
        return bundles;
    }

    /**
     * C_FILTER full-replace: swaps the device's entire registration set in one
     * transaction, so the bindings are never observed half done.
     */
    public void replaceRegistrations(String deviceAddress, List<Registration> entries) throws SQLException {
        try (Connection c = pool.getConnection()) {
            c.setAutoCommit(false);
            try {
                try (PreparedStatement del = c.prepareStatement(
                        "DELETE FROM notification_tokens WHERE device_address = ?")) {
                    del.setString(1, deviceAddress);
                    del.executeUpdate();
                }
                if (entries != null && !entries.isEmpty()) {
                    try (PreparedStatement ins = c.prepareStatement(
                            "INSERT INTO notification_tokens (routing_token, device_address, bundle_id, muted, issued_at) " +
                            "VALUES (?, ?, ?, ?, NOW()) " +
                            "ON CONFLICT (routing_token) DO UPDATE SET " +
                            "device_address = EXCLUDED.device_address, bundle_id = EXCLUDED.bundle_id, muted = EXCLUDED.muted")) {
                        for (Registration e : entries) {
                            ins.setBytes(1, e.routingKey());
                            ins.setString(2, deviceAddress);
                            ins.setString(3, e.bundleId());
                            ins.setBoolean(4, e.muted());
                            ins.addBatch();
                        }
                        ins.executeBatch();
                    }
                }
                try (PreparedStatement purge = c.prepareStatement(
                        "DELETE FROM queued_messages WHERE device_address = ? AND routing_key IN " +
                        "(SELECT routing_token FROM notification_tokens WHERE device_address = ? AND muted)")) {
                    purge.setString(1, deviceAddress);
                    purge.setString(2, deviceAddress);
                    purge.executeUpdate();
                }
                c.commit();
            } catch (SQLException e) {
                c.rollback();
                throw e;
            } finally {
                c.setAutoCommit(true);
            }
        }
        log.info("Registration set for {} replaced: {} entries", deviceAddress, entries == null ? 0 : entries.size());
    }

    public void queueEncryptedMessage(byte[] msgId, String deviceAddress, byte[] routingKey, byte[] ciphertext,
                                      byte[] iv, byte contentType, long expiresAt, long deviceSeq,
                                      byte priority, byte[] collapseKey) throws SQLException {
        final String sql = "INSERT INTO queued_messages (message_id, created_at, expires_at, device_seq, priority, " +
                "collapse_key, is_encrypted, ciphertext, content_type, iv, device_address, routing_key) " +
                "VALUES (?, NOW(), ?, ?, ?, ?, TRUE, ?, ?, ?, ?, ?)";
        try (Connection c = pool.getConnection()) {
            c.setAutoCommit(false);
            try {
                deleteSuperseded(c, deviceAddress, collapseKey);
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setBytes(1, msgId);
                    ps.setLong(2, expiresAt);
                    ps.setLong(3, deviceSeq);
                    ps.setShort(4, (short) (priority & 0xFF));
                    ps.setBytes(5, isBlankCollapseKey(collapseKey) ? null : collapseKey);
                    ps.setBytes(6, ciphertext);
                    ps.setShort(7, (short) (contentType & 0xFF));
                    ps.setBytes(8, iv);
                    ps.setString(9, deviceAddress);
                    ps.setBytes(10, routingKey);
                    ps.executeUpdate();
                }
                c.commit();
            } catch (SQLException e) { c.rollback(); throw e; } finally { c.setAutoCommit(true); }
        }
    }

    public void queuePlaintextMessage(byte[] msgId, String deviceAddress, byte[] routingKey, byte[] data,
                                      byte contentType, long expiresAt, long deviceSeq,
                                      byte priority, byte[] collapseKey) throws SQLException {
        final String sql = "INSERT INTO queued_messages (message_id, created_at, expires_at, device_seq, priority, " +
                "collapse_key, is_encrypted, data, content_type, device_address, routing_key) " +
                "VALUES (?, NOW(), ?, ?, ?, ?, FALSE, ?, ?, ?, ?)";
        try (Connection c = pool.getConnection()) {
            c.setAutoCommit(false);
            try {
                deleteSuperseded(c, deviceAddress, collapseKey);
                try (PreparedStatement ps = c.prepareStatement(sql)) {
                    ps.setBytes(1, msgId);
                    ps.setLong(2, expiresAt);
                    ps.setLong(3, deviceSeq);
                    ps.setShort(4, (short) (priority & 0xFF));
                    ps.setBytes(5, isBlankCollapseKey(collapseKey) ? null : collapseKey);
                    ps.setBytes(6, data);
                    ps.setShort(7, (short) (contentType & 0xFF));
                    ps.setString(8, deviceAddress);
                    ps.setBytes(9, routingKey);
                    ps.executeUpdate();
                }
                c.commit();
            } catch (SQLException e) { c.rollback(); throw e; } finally { c.setAutoCommit(true); }
        }
    }

    /**
     * Drops queued messages the incoming one supersedes. Only messages carrying
     * the SAME collapse key are replaced.
     */
    private void deleteSuperseded(Connection c, String deviceAddress, byte[] collapseKey) throws SQLException {
        if (isBlankCollapseKey(collapseKey)) return;
        try (PreparedStatement ps = c.prepareStatement(
                "DELETE FROM queued_messages WHERE device_address = ? AND collapse_key = ?")) {
            ps.setString(1, deviceAddress);
            ps.setBytes(2, collapseKey);
            ps.executeUpdate();
        }
    }

    private static boolean isBlankCollapseKey(byte[] key) {
        if (key == null) return true;
        for (byte b : key) if (b != 0) return false;
        return true;
    }

    /**
     * Unacknowledged messages, ascending by device_seq.
     *
     * @param afterSeq last seq the client durably processed, 0 sends everything
     */
    public List<QueuedMessage> getUnackedMessages(String deviceAddress, long afterSeq) throws SQLException {
        final String sql = "SELECT q.message_id, q.expires_at, q.device_seq, q.priority, q.is_encrypted, q.data, " +
                           "q.content_type, q.ciphertext, q.iv, q.routing_key FROM queued_messages q " +
                           "WHERE q.device_address = ? AND (q.expires_at = 0 OR q.expires_at > ?) AND q.device_seq > ? " +
                           "AND NOT EXISTS (SELECT 1 FROM notification_tokens t " +
                                           "WHERE t.routing_token = q.routing_key AND t.muted) " +
                           "ORDER BY q.device_seq ASC";
        List<QueuedMessage> result = new ArrayList<>();
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, deviceAddress);
            ps.setLong(2, Instant.now().getEpochSecond());
            ps.setLong(3, afterSeq);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    result.add(new QueuedMessage(
                            rs.getBytes("message_id"), rs.getLong("expires_at"), rs.getLong("device_seq"),
                            (byte) rs.getShort("priority"), rs.getBoolean("is_encrypted"), rs.getBytes("data"),
                            (byte) rs.getShort("content_type"), rs.getBytes("ciphertext"), rs.getBytes("iv"),
                            rs.getBytes("routing_key")));
                }
            }
        }
        return result;
    }

    public void ackMessage(byte[] msgId, String deviceAddress) throws SQLException {
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(
                "DELETE FROM queued_messages WHERE message_id = ? AND device_address = ?")) {
            ps.setBytes(1, msgId); ps.setString(2, deviceAddress); ps.executeUpdate();
        }
    }

    public int purgeExpiredMessages() throws SQLException {
        try (Connection c = pool.getConnection(); PreparedStatement ps = c.prepareStatement(
                "DELETE FROM queued_messages WHERE expires_at > 0 AND expires_at <= ?")) {
            ps.setLong(1, Instant.now().getEpochSecond());
            return ps.executeUpdate();
        }
    }

    private static RSAPublicKey decodePublicKey(byte[] der) throws SQLException {
        try {
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new SQLException("Failed to decode key", e);
        }
    }

    public record Device(String deviceAddress, RSAPublicKey publicKey) {}

    public record NotificationToken(byte[] routingToken, String deviceAddress, String bundleId,
                                    boolean muted, Instant issuedAt) {}

    public record Registration(byte[] routingKey, String bundleId, boolean muted) {}

    public record QueuedMessage(byte[] messageId, long expiresAt, long deviceSeq, byte priority,
                                boolean isEncrypted, byte[] data, byte contentType,
                                byte[] ciphertext, byte[] iv, byte[] routingKey) {}
}

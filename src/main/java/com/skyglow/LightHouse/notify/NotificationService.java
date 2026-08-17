package com.skyglow.LightHouse.notify;

import com.skyglow.LightHouse.SGPProtocol;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.router.Router;
import com.skyglow.LightHouse.router.Router.NotificationEnvelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.SecureRandom;
import java.sql.SQLException;

/**
 * The one path a notification takes into the system, allocate a message id and
 * device sequence, optionally persist for offline delivery, then hand it to the
 * {@link Router}. Every producer goes through here.
 */
public final class NotificationService {

    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);

    private final Database db;
    private final Router   router;
    private final SecureRandom rng = new SecureRandom();

    public NotificationService(Database db, Router router) {
        this.db     = db;
        this.router = router;
    }

    /**
     * One notification to dispatch.
     *
     * @param payload     plaintext, or ciphertext followed by the GCM tag
     * @param iv          12-byte GCM nonce, required when encrypted, else null
     * @param expiresAt   Unix seconds, 0 means never
     * @param priority    server-side queue ordering only, never a wire flag
     * @param collapseKey 16 bytes, replaces any queued message with the same key. Null for none
     * @param store       false delivers only if the device is connected right now
     */
    public record Message(
            String  deviceAddress,
            byte[]  routingKey,
            byte[]  payload,
            byte[]  iv,
            boolean encrypted,
            byte    contentType,
            long    expiresAt,
            byte    priority,
            byte[]  collapseKey,
            boolean store
    ) {}

    public record Receipt(byte[] msgId, long deviceSeq, boolean live) {}

    public static int maxPayloadBytes(boolean encrypted) {
        return SGPProtocol.MAX_PAYLOAD - SGPProtocol.NOTIFY_MIN_PAYLOAD
                - (encrypted ? SGPProtocol.GCM_IV_LEN : 0);
    }

    public Receipt dispatch(Message m) throws SQLException {
        byte[] msgId     = newMessageId();
        long   deviceSeq = db.nextDeviceSeq(m.deviceAddress());

        if (m.store()) {
            if (m.encrypted()) {
                db.queueEncryptedMessage(msgId, m.deviceAddress(), m.routingKey(), m.payload(), m.iv(),
                        m.contentType(), m.expiresAt(), deviceSeq, m.priority(), m.collapseKey());
            } else {
                db.queuePlaintextMessage(msgId, m.deviceAddress(), m.routingKey(), m.payload(),
                        m.contentType(), m.expiresAt(), deviceSeq, m.priority(), m.collapseKey());
            }
        }

        boolean live = router.deliver(m.deviceAddress(), new NotificationEnvelope(
                msgId, m.routingKey(), deviceSeq, m.expiresAt(),
                m.encrypted(), m.priority(), m.contentType(), m.payload(), m.iv()));

        log.info("Notification dispatched to {} (live={}, stored={})", m.deviceAddress(), live, m.store());
        return new Receipt(msgId, deviceSeq, live);
    }

    public byte[] newMessageId() {
        byte[] id = new byte[SGPProtocol.MSG_ID_LEN];
        rng.nextBytes(id);
        return id;
    }
}

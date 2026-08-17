package com.skyglow.LightHouse.router;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Maps device addresses to the send callback of their live connection. The
 * callback is a Consumer rather than a channel so the router has no dependency
 * on the connection implementation.
 */
public final class Router {

    private static final Logger log = LoggerFactory.getLogger(Router.class);

    private final ConcurrentHashMap<String, Consumer<NotificationEnvelope>> connections = new ConcurrentHashMap<>();

    /**
     * A notification ready to be written to a client.
     *
     * @param priority    server-side queue ordering only, never a wire flag
     * @param contentType SGPProtocol.CT_*, matching the client's SGPayloadFormat
     * @param data        plaintext, or ciphertext followed by the GCM tag
     * @param iv          12-byte GCM nonce, null when not encrypted
     */
    public record NotificationEnvelope(
            byte[]  msgId,
            byte[]  routingKey,
            long    deviceSeq,
            long    expiresAt,
            boolean isEncrypted,
            byte    priority,
            byte    contentType,
            byte[]  data,
            byte[]  iv
    ) {}

    /**
     * Atomically replaces any earlier connection for the device, invoking the
     * displaced callback with a null envelope.
     */
    public void register(String deviceAddress, Consumer<NotificationEnvelope> sendCallback) {
        Consumer<NotificationEnvelope> old = connections.put(deviceAddress, sendCallback);
        if (old != null) {
            log.info("Replacing existing connection for {}", deviceAddress);
            try { old.accept(null); } catch (Exception ignored) {}
        }
    }

    /** dead if the connection was already replaced by a different one. */
    public void unregister(String deviceAddress, Consumer<NotificationEnvelope> sendCallback) {
        connections.remove(deviceAddress, sendCallback);
    }

    /** False means no live connection took it and the caller must rely on the DB queue. */
    public boolean deliver(String deviceAddress, NotificationEnvelope envelope) {
        Consumer<NotificationEnvelope> callback = connections.get(deviceAddress);
        if (callback == null) return false;
        try {
            callback.accept(envelope);
            return true;
        } catch (Exception e) {
            log.warn("Delivery callback threw for {}: {}", deviceAddress, e.getMessage());
            return false;
        }
    }

    public int connectedCount() { return connections.size(); }

    public Set<String> getConnectedDevices() { return connections.keySet(); }
}

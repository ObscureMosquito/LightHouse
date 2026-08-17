package com.skyglow.LightHouse;

import com.skyglow.LightHouse.SGPProtocol.*;
import com.skyglow.LightHouse.config.ServerConfig;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.db.Database.*;
import com.skyglow.LightHouse.event.ServerEvents;
import com.skyglow.LightHouse.router.Router;
import com.skyglow.LightHouse.router.Router.NotificationEnvelope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import java.io.*;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.zip.Deflater;

/**
 * Drives the SGP/2 protocol for one client on its own virtual thread: frame
 * I/O, the registration and authentication state machine, keep-alive, and
 * writing routed notifications to the socket.
 */
public final class SGPConnection implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(SGPConnection.class);

    private enum State { CONNECTED, REGISTERING, AUTHENTICATING, AUTHENTICATED, CLOSED }

    private record OutboundFrame(byte type, byte[] payload) {}
    private static final OutboundFrame POISON = new OutboundFrame(MsgType.S_DISCONNECT, null);

    private static final int MAX_FILTER_ENTRIES  = 5000;
    private static final int MAX_BUNDLE_ID_BYTES = 255;

    /** Skew past which a post-auth S_TIME_SYNC corrects the client clock. */
    private static final long TIME_SYNC_THRESHOLD_SEC = 2;

    /**
     * Replay is impossible regardless of the timestamp, since the signature
     * covers a fresh nonce, so this is only a sanity bound. It is set to the
     * largest offset a client accepts from S_TIME_SYNC. Rejecting at the 300 s
     * challenge window would permanently brick drifted devices: AUTH_FAIL is
     * terminal to the client and S_TIME_SYNC is only accepted after
     * authenticating.
     */
    private static final long MAX_AUTH_SKEW_SEC = 172_800;

    private static final int ADDR_ALLOC_ATTEMPTS = 5;

    /** Generous: first-time registration may block on RSA-2048 keygen on old hardware. */
    private static final int HANDSHAKE_TIMEOUT_MS = 300 * 1000;

    /** The client's adaptive keep-alive legitimately goes quiet for 600 to 3600 s. */
    private static final int IDLE_PROBE_TIMEOUT_MS =
            (SGPProtocol.PING_INTERVAL_SEC + SGPProtocol.PONG_TIMEOUT_SEC) * 1000;

    private static final int  PROBE_GRACE_MS     = SGPProtocol.PONG_TIMEOUT_SEC * 1000;
    private static final int  COMPRESS_MIN_BYTES = 256;
    private static final long ENQUEUE_TIMEOUT_MS = 5_000;

    private final SSLSocket    socket;
    private final ServerConfig config;
    private final Database     db;
    private final Router       router;
    private final ServerEvents events;
    private final SecureRandom rng = new SecureRandom();

    private final LinkedBlockingQueue<OutboundFrame> sendQueue = new LinkedBlockingQueue<>(256);
    private DataInputStream in;
    private OutputStream    out;

    private volatile State state = State.CONNECTED;
    private String  deviceAddress;
    private Device  device;
    private byte[]  pendingNonce;
    private long    loginTimestamp;
    private byte[]  pendingRegPubKeyDer;
    private String  regCertSubject;

    /** Accumulates C_FILTER chunks until the final has_more = 0 chunk arrives. */
    private List<Registration> pendingFilterEntries;

    private boolean probeOutstanding = false;
    private long    probeSeq = 0;

    private Consumer<NotificationEnvelope> routerCallback;

    public SGPConnection(SSLSocket socket, ServerConfig config, Database db, Router router, ServerEvents events) {
        this.socket = socket;
        this.config = config;
        this.db     = db;
        this.router = router;
        this.events = events;
    }

    @Override
    public void run() {
        String remote = socket.getRemoteSocketAddress().toString();
        log.info("[{}] Connected", remote);

        try {
            in  = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            out = new BufferedOutputStream(socket.getOutputStream());

            Thread sender = Thread.ofVirtual().name("sgp-sender-" + remote).start(this::senderLoop);
            sendHello();

            socket.setSoTimeout(HANDSHAKE_TIMEOUT_MS);
            readerLoop(remote);

            sendQueue.offer(POISON, 1, TimeUnit.SECONDS);
            sender.join(3_000);

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.warn("[{}] Unexpected error: {}", remote, e.getMessage(), e);
        } finally {
            cleanup(remote);
        }
    }

    /**
     * Reads frames until the connection closes. Any inbound traffic clears an
     * outstanding liveness probe, not just C_PONG. A read timeout while
     * authenticated triggers one S_PING probe before the connection is declared
     * dead, because the client's keep-alive interval can exceed ours.
     */
    private void readerLoop(String remote) {
        while (state != State.CLOSED) {
            try {
                Frame frame = SGPProtocol.readFrame(in);
                if (probeOutstanding) {
                    probeOutstanding = false;
                    setSoTimeoutQuietly(IDLE_PROBE_TIMEOUT_MS);
                }
                log.debug("[{}] recv {} ({} bytes)", remote, MsgType.name(frame.type()), frame.payloadLen());
                dispatch(frame, remote);

            } catch (SocketTimeoutException e) {
                if (state == State.AUTHENTICATED && !probeOutstanding) {
                    probeOutstanding = true;
                    enqueue(MsgType.S_PING, new PayloadBuilder().putI64(++probeSeq).build());
                    setSoTimeoutQuietly(PROBE_GRACE_MS);
                    continue;
                }
                if (state == State.AUTHENTICATED) {
                    log.warn("[{}] Liveness probe unanswered, dead connection", remote);
                }
                state = State.CLOSED;

            } catch (IOException e) {
                state = State.CLOSED;

            } catch (SGPProtocolException e) {
                log.warn("[{}] Protocol error: {}", remote, e.getMessage());
                sendDisconnect(DiscReason.PROTOCOL);
                state = State.CLOSED;

            } catch (RuntimeException e) {
                log.warn("[{}] Malformed frame: {}", remote, e.toString());
                sendDisconnect(DiscReason.PROTOCOL);
                state = State.CLOSED;
            }
        }
    }

    /** A write failure closes the socket to unblock the reader. */
    private void senderLoop() {
        try {
            while (true) {
                OutboundFrame frame = sendQueue.take();
                if (frame == POISON) break;
                try {
                    SGPProtocol.writeFrame(out, frame.type(), frame.payload());
                } catch (IOException e) {
                    log.warn("Write error: {}", e.getMessage());
                    state = State.CLOSED;
                    closeSocketQuietly();
                    break;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /**
     * Enforces the protocol phase machine: each message type is accepted only in
     * the state that solicited it, mirroring the client's own phase gating.
     * C_DISCONNECT is always honoured, and extension types at or above 0x30 are
     * ignored so future additions do not kill old servers.
     */
    private void dispatch(Frame frame, String remote) throws SGPProtocolException {
        byte type = frame.type();
        if (type == MsgType.C_DISCONNECT) { state = State.CLOSED; return; }

        switch (state) {
            case CONNECTED -> {
                switch (type) {
                    case MsgType.C_REGISTER -> handleRegister(frame, remote);
                    case MsgType.C_LOGIN    -> handleLogin(frame, remote);
                    default -> throw unexpected(type);
                }
            }
            case REGISTERING -> {
                if (type == MsgType.C_REGISTER_RESP) handleRegisterResp(frame, remote);
                else throw unexpected(type);
            }
            case AUTHENTICATING -> {
                if (type == MsgType.C_LOGIN_RESP) handleLoginResp(frame);
                else throw unexpected(type);
            }
            case AUTHENTICATED -> {
                switch (type) {
                    case MsgType.C_POLL   -> handlePoll(
                            frame.payloadLen() >= SGPProtocol.C_POLL_LAST_SEQ_SIZE ? frame.readI64(0) : 0L);
                    case MsgType.C_ACK    -> handleAck(frame);
                    case MsgType.C_FILTER -> handleFilter(frame, remote);
                    case MsgType.C_PING   -> handleClientPing(frame);
                    case MsgType.C_PONG   -> log.debug("[{}] C_PONG", remote);
                    default -> {
                        if ((type & 0xFF) >= 0x30) log.debug("[{}] Ignoring unknown type {}", remote, MsgType.name(type));
                        else throw unexpected(type);
                    }
                }
            }
            case CLOSED -> { }
        }
    }

    private static SGPProtocolException unexpected(byte type) {
        return new SGPProtocolException("Unexpected message: " + MsgType.name(type));
    }

    /**
     * C_REGISTER: keyLen(2), pubkey DER, ts(8), ver(4). Protocol v2 sends no
     * address, the server owns the namespace and assigns one.
     *
     * When a registration CA is configured, only a connection that presented a
     * validated client certificate may register. Invalid certificates never get
     * here (the handshake fails) and login connections present none, so presence
     * is the whole gate.
     */
    private void handleRegister(Frame frame, String remote) throws SGPProtocolException {
        if (config.requireRegCert()) {
            regCertSubject = verifiedClientCertSubject();
            if (regCertSubject == null) {
                log.info("[{}] Rejecting registration: no authorized client certificate", remote);
                sendRegisterFail((byte) 0x05, "Authorized client certificate required");
                state = State.CLOSED; return;
            }
        }

        int offset = 0;
        int keyLen = frame.readU16(offset); offset += 2;
        if (keyLen < 128 || keyLen > 800) throw new SGPProtocolException("Bad key length");
        if (offset + keyLen + 12 > frame.payloadLen()) throw new SGPProtocolException("C_REGISTER truncated");
        byte[] pubKeyDer = frame.slice(offset, keyLen); offset += keyLen;

        long timestamp = frame.readI64(offset); offset += 8;
        long protoVer  = frame.readU32(offset);

        if (protoVer != SGPProtocol.VERSION) {
            log.info("[{}] Rejecting registration: protocol version {} != {}", remote, protoVer, SGPProtocol.VERSION);
            sendDisconnect(DiscReason.VERSION_MISMATCH);
            state = State.CLOSED; return;
        }
        if (Math.abs(Instant.now().getEpochSecond() - timestamp) > MAX_AUTH_SKEW_SEC) {
            sendRegisterFail((byte) 0x04, "Timestamp out of window");
            state = State.CLOSED; return;
        }

        try {
            RSAPublicKey pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pubKeyDer));
            if (pub.getModulus().bitLength() < 2048) {
                sendRegisterFail((byte) 0x02, "Key too short");
                state = State.CLOSED; return;
            }
        } catch (Exception e) {
            sendRegisterFail((byte) 0x02, "Invalid key or server err");
            state = State.CLOSED; return;
        }

        pendingRegPubKeyDer = pubKeyDer;
        loginTimestamp      = timestamp;
        pendingNonce        = generateNonce();
        state               = State.REGISTERING;
        enqueue(MsgType.S_CHALLENGE, pendingNonce);
    }

    /**
     * Verifies the registration signature and assigns an address. During
     * registration no address is bound yet, so the client signs nonce and
     * timestamp only. Afterwards the connection returns to the unauthenticated
     * state: the client re-authenticates with the assigned address, possibly on
     * a fresh connection.
     */
    private void handleRegisterResp(Frame frame, String remote) throws SGPProtocolException {
        long timestamp = frame.readI64(0);
        if (timestamp != loginTimestamp) {
            sendRegisterFail((byte) 0x03, "Timestamp mismatch");
            state = State.CLOSED; return;
        }

        byte[] sig = readSignature(frame);

        RSAPublicKey pub;
        try {
            pub = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pendingRegPubKeyDer));
            if (!verifyPSS(pub, pendingNonce, new byte[0], loginTimestamp, sig)) {
                sendRegisterFail((byte) 0x03, "Signature failed");
                state = State.CLOSED; return;
            }
        } catch (Exception e) {
            sendRegisterFail((byte) 0x02, "Invalid key");
            state = State.CLOSED; return;
        }

        String assigned = allocateAddress(pub);
        if (assigned == null) {
            sendRegisterFail((byte) 0x02, "Could not allocate address");
            state = State.CLOSED; return;
        }

        byte[] addrBytes = assigned.getBytes(StandardCharsets.UTF_8);
        enqueue(MsgType.S_REGISTER_OK, new PayloadBuilder()
                .putU32(SGPProtocol.VERSION)
                .putU16(addrBytes.length)
                .putBytes(addrBytes)
                .build());
        log.info("[{}] Registered new device as {}{}", remote, assigned,
                regCertSubject != null ? " (authorized by cert: " + regCertSubject + ")" : "");

        state = State.CONNECTED;
        pendingRegPubKeyDer = null;
        pendingNonce = null;
    }

    /** Mints a 32-hex-char address at the server domain, charset-safe per the client's whitelist. */
    private String allocateAddress(RSAPublicKey pub) {
        for (int attempt = 0; attempt < ADDR_ALLOC_ATTEMPTS; attempt++) {
            byte[] raw = new byte[16];
            rng.nextBytes(raw);
            String candidate = HexFormat.of().formatHex(raw) + "@" + config.serverAddress();
            try {
                db.createDevice(candidate, pub, regCertSubject);
                return candidate;
            } catch (SQLException dup) {
                log.debug("Address allocation attempt {} failed: {}", attempt, dup.getMessage());
            }
        }
        return null;
    }

    /** The TLS layer already PKIX-validated it, so presence implies validity. */
    private String verifiedClientCertSubject() {
        try {
            Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate x509) {
                return x509.getSubjectX500Principal().getName();
            }
        } catch (SSLPeerUnverifiedException none) {
            return null;
        }
        return null;
    }

    private void sendRegisterFail(byte reasonCode, String reason) {
        byte[] reasonBytes = reason.getBytes(StandardCharsets.UTF_8);
        enqueue(MsgType.S_REGISTER_FAIL, new PayloadBuilder()
                .putByte(reasonCode)
                .putU16(reasonBytes.length)
                .putBytes(reasonBytes)
                .build());
    }

    /**
     * C_LOGIN: addrLen(2), address, ts(8), ver(4).
     *
     * Uncorrectable clock skew is a soft failure on purpose: AUTH_FAIL is
     * terminal to the client, and a clock problem must not brick the device.
     */
    private void handleLogin(Frame frame, String remote) throws SGPProtocolException {
        int offset  = 0;
        int addrLen = frame.readU16(offset); offset += 2;
        if (addrLen == 0 || addrLen > 255 || offset + addrLen + 12 > frame.payloadLen()) {
            throw new SGPProtocolException("C_LOGIN malformed");
        }
        deviceAddress = new String(frame.slice(offset, addrLen), StandardCharsets.UTF_8);
        offset += addrLen;
        loginTimestamp = frame.readI64(offset); offset += 8;
        long protoVer  = frame.readU32(offset);

        if (protoVer != SGPProtocol.VERSION) {
            log.info("[{}] Rejecting login: protocol version {} != {}", remote, protoVer, SGPProtocol.VERSION);
            sendDisconnect(DiscReason.VERSION_MISMATCH);
            state = State.CLOSED; return;
        }

        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - loginTimestamp) > MAX_AUTH_SKEW_SEC) {
            log.info("[{}] Login timestamp skewed by {}s, soft-rejecting", remote, now - loginTimestamp);
            sendDisconnectWithRetry(DiscReason.PROTOCOL, 600L);
            state = State.CLOSED; return;
        }

        try {
            Optional<Device> dev = db.getDevice(deviceAddress);
            if (dev.isEmpty()) {
                sendDisconnectWithRetry(DiscReason.AUTH_FAIL, 0L);
                state = State.CLOSED; return;
            }
            device = dev.get();
        } catch (SQLException e) {
            sendDisconnect(DiscReason.SERVER_ERR);
            state = State.CLOSED; return;
        }

        pendingNonce = generateNonce();
        state = State.AUTHENTICATING;
        enqueue(MsgType.S_CHALLENGE, pendingNonce);
    }

    /**
     * Verifies the login signature and brings the connection up. A timestamp
     * mismatch is a hiccup rather than a credential failure, so it disconnects
     * soft and the client retries. S_TIME_SYNC is only valid post-auth, so drift
     * is corrected here before it can breach the challenge window.
     */
    private void handleLoginResp(Frame frame) throws SGPProtocolException {
        long timestamp = frame.readI64(0);
        if (timestamp != loginTimestamp) {
            sendDisconnect(DiscReason.PROTOCOL);
            state = State.CLOSED; return;
        }

        byte[] sig = readSignature(frame);
        try {
            if (!verifyPSS(device.publicKey(), pendingNonce,
                    deviceAddress.getBytes(StandardCharsets.UTF_8), loginTimestamp, sig)) {
                sendDisconnect(DiscReason.AUTH_FAIL);
                state = State.CLOSED; return;
            }
        } catch (Exception e) {
            sendDisconnect(DiscReason.AUTH_FAIL);
            state = State.CLOSED; return;
        }

        state = State.AUTHENTICATED;
        pendingNonce = null;
        setSoTimeoutQuietly(IDLE_PROBE_TIMEOUT_MS);
        routerCallback = this::deliverNotification;
        router.register(deviceAddress, routerCallback);
        events.deviceConnected(deviceAddress, System.currentTimeMillis());
        enqueue(MsgType.S_AUTH_OK, null);

        long now = Instant.now().getEpochSecond();
        if (Math.abs(now - loginTimestamp) > TIME_SYNC_THRESHOLD_SEC) {
            enqueue(MsgType.S_TIME_SYNC, new PayloadBuilder().putI64(now).build());
        }
    }

    /** Reads the sigLen(2) and signature tail shared by both response frames. */
    private static byte[] readSignature(Frame frame) throws SGPProtocolException {
        int sigLen = frame.readU16(8);
        if (sigLen == 0 || sigLen > 600 || 10 + sigLen > frame.payloadLen()) {
            throw new SGPProtocolException("Bad sig length");
        }
        return frame.slice(10, sigLen);
    }

    /**
     * Drains the device's offline queue.
     *
     * @param afterSeq last device_seq the client durably processed, 0 sends everything
     */
    private void handlePoll(long afterSeq) {
        try {
            for (QueuedMessage msg : db.getUnackedMessages(deviceAddress, afterSeq)) enqueueNotification(msg);
        } catch (SQLException e) {
            sendDisconnect(DiscReason.SERVER_ERR);
            state = State.CLOSED;
            return;
        }
        enqueue(MsgType.S_POLL_DONE, null);
    }

    private void handleAck(Frame frame) throws SGPProtocolException {
        if (frame.payloadLen() < SGPProtocol.MSG_ID_LEN + 1) throw new SGPProtocolException("C_ACK payload too short");
        byte[] msgId  = frame.slice(0, SGPProtocol.MSG_ID_LEN);
        int    status = frame.payload()[SGPProtocol.MSG_ID_LEN] & 0xFF;
        try { db.ackMessage(msgId, deviceAddress); } catch (SQLException ignored) {}
        events.ack(msgId, status, System.currentTimeMillis());
    }

    private void handleClientPing(Frame frame) {
        byte[] seq = frame.payloadLen() >= SGPProtocol.PING_SEQ_LEN
                ? frame.slice(0, SGPProtocol.PING_SEQ_LEN)
                : new byte[SGPProtocol.PING_SEQ_LEN];
        enqueue(MsgType.S_PONG, seq);
    }

    /**
     * C_FILTER: flags(1), count(2), then count entries of tag(1),
     * routing_key(32), bid_len(2), bundle_id. The whole multi-chunk transmission
     * is one atomic full-replace, and tag 0x02 means muted: the binding is kept
     * but delivery is suppressed. A connection that drops mid-transmission
     * discards the buffer for free, since it lives only on this object.
     */
    private void handleFilter(Frame frame, String remote) throws SGPProtocolException {
        if (frame.payloadLen() < 3) throw new SGPProtocolException("C_FILTER payload too short");

        boolean hasMore = (frame.payload()[0] & 0x01) != 0;
        int     count   = frame.readU16(1);

        if (pendingFilterEntries == null) pendingFilterEntries = new ArrayList<>();
        if (pendingFilterEntries.size() + count > MAX_FILTER_ENTRIES) {
            throw new SGPProtocolException("Exceeded maximum allowed registration entries");
        }

        final int plen = frame.payloadLen();
        int offset = 3;
        for (int i = 0; i < count; i++) {
            if (offset + 1 + SGPProtocol.ROUTING_KEY_LEN + 2 > plen) {
                throw new SGPProtocolException("C_FILTER entry header overruns payload");
            }
            int tag = frame.payload()[offset] & 0xFF; offset += 1;
            byte[] routingKey = frame.slice(offset, SGPProtocol.ROUTING_KEY_LEN);
            offset += SGPProtocol.ROUTING_KEY_LEN;
            int bidLen = frame.readU16(offset); offset += 2;
            if (bidLen > MAX_BUNDLE_ID_BYTES) throw new SGPProtocolException("C_FILTER bundle_id too long: " + bidLen);
            if (offset + bidLen > plen) throw new SGPProtocolException("C_FILTER bundle_id overruns payload");
            String bundleId = new String(frame.slice(offset, bidLen), StandardCharsets.UTF_8);
            offset += bidLen;

            pendingFilterEntries.add(new Registration(routingKey, bundleId, tag == 0x02));
        }

        if (hasMore) {
            log.debug("[{}] C_FILTER chunk: {} entries (more coming)", remote, count);
            return;
        }

        List<Registration> active = pendingFilterEntries;
        pendingFilterEntries = null;
        if (deviceAddress != null) {
            try {
                db.replaceRegistrations(deviceAddress, active);
            } catch (SQLException e) {
                log.warn("[{}] Registration full-replace failed: {}", remote, e.getMessage());
            }
        }
        log.info("[{}] Registration set replaced: {} entries", remote, active.size());
    }

    /** A null envelope is the router's poison pill telling this connection to close. */
    private void deliverNotification(NotificationEnvelope env) {
        if (env == null) { sendDisconnect(DiscReason.REPLACED); state = State.CLOSED; return; }
        enqueueNotification(env.routingKey(), env.msgId(), env.deviceSeq(), env.expiresAt(),
                env.isEncrypted(), env.contentType(), env.data(), env.iv());
    }

    private void enqueueNotification(QueuedMessage msg) {
        enqueueNotification(msg.routingKey(), msg.messageId(), msg.deviceSeq(), msg.expiresAt(),
                msg.isEncrypted(), msg.contentType(),
                msg.isEncrypted() ? msg.ciphertext() : msg.data(), msg.iv());
    }

    /**
     * Builds and enqueues one S_NOTIFY frame.
     *
     * Wire flags carry only encryption and compression, priority is server-side
     * queue state. 
     */
    private void enqueueNotification(byte[] routingKey, byte[] msgId, long deviceSeq, long expiresAt,
                                     boolean encrypted, byte contentType, byte[] data, byte[] iv) {
        if (data == null) data = new byte[0];
        byte flags = 0;

        if (encrypted) {
            if (iv == null || iv.length != SGPProtocol.GCM_IV_LEN) {
                log.error("Skipping encrypted notification with missing/invalid IV (msgId={})",
                        HexFormat.of().formatHex(msgId));
                return;
            }
            flags |= SGPProtocol.NOTIFY_FLAG_ENCRYPTED;
        } else if (data.length >= COMPRESS_MIN_BYTES) {
            byte[] deflated = deflateIfSmaller(data);
            if (deflated != null) {
                data = deflated;
                flags |= SGPProtocol.NOTIFY_FLAG_COMPRESSED;
            }
        }

        int totalLen = SGPProtocol.NOTIFY_MIN_PAYLOAD + data.length + (encrypted ? SGPProtocol.GCM_IV_LEN : 0);
        if (totalLen > SGPProtocol.MAX_PAYLOAD) {
            log.error("Skipping oversized notification: {} bytes (msgId={})",
                    totalLen, HexFormat.of().formatHex(msgId));
            return;
        }

        PayloadBuilder pb = new PayloadBuilder()
                .putBytes(routingKey).putBytes(msgId).putI64(deviceSeq).putI64(expiresAt)
                .putByte(flags).putByte(contentType).putU32(data.length).putBytes(data);
        if (encrypted) pb.putBytes(iv);

        enqueue(MsgType.S_NOTIFY, pb.build());
    }

    /** Raw DEFLATE with no wrapper, since the client inflates with windowBits -15 */
    private static byte[] deflateIfSmaller(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION, true);
        try {
            deflater.setInput(data);
            deflater.finish();
            byte[] out = new byte[data.length - 1];
            int len = 0;
            while (!deflater.finished()) {
                int n = deflater.deflate(out, len, out.length - len);
                if (n == 0) return null;
                len += n;
            }
            return Arrays.copyOf(out, len);
        } finally {
            deflater.end();
        }
    }

    private void sendHello() {
        enqueue(MsgType.S_HELLO, new PayloadBuilder().putU32(SGPProtocol.VERSION).build());
    }

    private void sendDisconnect(byte reason) {
        sendDisconnectWithRetry(reason, retryAfterForReason(reason));
    }

    private void sendDisconnectWithRetry(byte reason, long retryAfterSec) {
        enqueue(MsgType.S_DISCONNECT, new PayloadBuilder().putByte(reason).putU32(retryAfterSec).build());
    }

    private long retryAfterForReason(byte reason) {
        return switch (reason) {
            case DiscReason.NORMAL     -> 0L;
            case DiscReason.REPLACED   -> 1L + rng.nextInt(3);
            case DiscReason.SERVER_ERR -> 5L + rng.nextInt(30);
            case DiscReason.PROTOCOL   -> 30L + rng.nextInt(30);
            default -> SGPProtocol.DISCONNECT_NO_RETRY;
        };
    }

    /** Queues a frame, a queue that stays full closes the connection rather than dropping the frame */
    private void enqueue(byte type, byte[] payload) {
        try {
            if (sendQueue.offer(new OutboundFrame(type, payload), ENQUEUE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) return;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        }
        log.warn("Send queue full for {} ms, closing stuck connection", ENQUEUE_TIMEOUT_MS);
        state = State.CLOSED;
        closeSocketQuietly();
    }

    private void cleanup(String remote) {
        state = State.CLOSED;
        if (routerCallback != null && deviceAddress != null) {
            router.unregister(deviceAddress, routerCallback);
            events.deviceDisconnected(deviceAddress, System.currentTimeMillis());
        }
        closeSocketQuietly();
        log.info("[{}] Disconnected", remote);
    }

    private void setSoTimeoutQuietly(int millis) {
        try { socket.setSoTimeout(millis); } catch (java.net.SocketException ignored) {}
    }

    private void closeSocketQuietly() {
        try { socket.close(); } catch (IOException ignored) {}
    }

    private byte[] generateNonce() {
        byte[] nonce = new byte[SGPProtocol.NONCE_LEN];
        rng.nextBytes(nonce);
        return nonce;
    }

    /** Verifies RSASSA-PSS over nonce, address, timestamp(BE). */
    private static boolean verifyPSS(PublicKey pubKey, byte[] nonce, byte[] addrUtf8,
                                     long timestamp, byte[] sig) throws Exception {
        Signature verifier = Signature.getInstance("RSASSA-PSS");
        verifier.setParameter(new PSSParameterSpec(
                "SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1));
        verifier.initVerify(pubKey);
        verifier.update(nonce);
        verifier.update(addrUtf8);
        byte[] tsBE = new byte[8];
        for (int i = 7; i >= 0; i--) { tsBE[i] = (byte) (timestamp & 0xFF); timestamp >>= 8; }
        verifier.update(tsBE);
        return verifier.verify(sig);
    }
}

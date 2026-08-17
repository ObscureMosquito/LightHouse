package com.skyglow.LightHouse;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/** Skyglow Protocol version 2 (SGP/2) constants and framing. */
public final class SGPProtocol {

    private SGPProtocol() {}

    public static final byte MAGIC        = 0x53;
    public static final byte VERSION      = 0x02;
    public static final int  HEADER_SIZE  = 8;
    public static final int  MAX_PAYLOAD  = 4096;
    public static final int ROUTING_KEY_LEN  = 32;
    public static final int MSG_ID_LEN       = 16;
    public static final int NONCE_LEN        = 32;
    public static final int PING_SEQ_LEN     = 8;
    public static final int GCM_IV_LEN       = 12;
    public static final int COLLAPSE_KEY_LEN = 16;
    public static final long DISCONNECT_NO_RETRY = 0xFFFFFFFFL;
    public static final int PING_INTERVAL_SEC    = 900;
    public static final int PONG_TIMEOUT_SEC     = 15;
    public static final byte CT_TLV       = 0x00;
    public static final byte CT_JSON      = 0x01;
    public static final byte CT_PLIST     = 0x02;
    public static final byte CT_TLVSTRUCT = 0x03;
    public static final int NOTIFY_OFF_ROUTING_KEY  = 0;
    public static final int NOTIFY_OFF_MSG_ID       = 32;
    public static final int NOTIFY_OFF_SEQ          = 48;
    public static final int NOTIFY_OFF_EXPIRES_AT   = 56;
    public static final int NOTIFY_OFF_FLAGS        = 64;
    public static final int NOTIFY_OFF_CONTENT_TYPE = 65;
    public static final int NOTIFY_OFF_DATA_LEN     = 66;
    public static final int NOTIFY_OFF_DATA         = 70;
    public static final int NOTIFY_MIN_PAYLOAD      = 70;

    public static final class MsgType {
        private MsgType() {}
        public static final byte S_HELLO         = 0x10;
        public static final byte S_CHALLENGE     = 0x11;
        public static final byte S_AUTH_OK       = 0x12;
        public static final byte S_NOTIFY        = 0x13;
        public static final byte S_DISCONNECT    = 0x14;
        public static final byte S_PONG          = 0x16;
        public static final byte S_POLL_DONE     = 0x17;
        public static final byte S_REGISTER_OK   = 0x18;
        public static final byte S_REGISTER_FAIL = 0x19;
        public static final byte S_PING          = 0x1A;
        public static final byte S_TIME_SYNC     = 0x1B;
        public static final byte C_LOGIN         = 0x20;
        public static final byte C_LOGIN_RESP    = 0x21;
        public static final byte C_POLL          = 0x22;
        public static final byte C_ACK           = 0x23;
        public static final byte C_DISCONNECT    = 0x24;
        public static final byte C_PING          = 0x27;
        public static final byte C_REGISTER      = 0x28;
        public static final byte C_REGISTER_RESP = 0x29;
        public static final byte C_PONG          = 0x2A;
        public static final byte C_FILTER        = 0x2B;

        public static String name(byte type) {
            return switch (type) {
                case S_HELLO         -> "S_HELLO";
                case S_CHALLENGE     -> "S_CHALLENGE";
                case S_AUTH_OK       -> "S_AUTH_OK";
                case S_NOTIFY        -> "S_NOTIFY";
                case S_DISCONNECT    -> "S_DISCONNECT";
                case S_PONG          -> "S_PONG";
                case S_POLL_DONE     -> "S_POLL_DONE";
                case S_REGISTER_OK   -> "S_REGISTER_OK";
                case S_REGISTER_FAIL -> "S_REGISTER_FAIL";
                case S_PING          -> "S_PING";
                case S_TIME_SYNC     -> "S_TIME_SYNC";
                case C_LOGIN         -> "C_LOGIN";
                case C_LOGIN_RESP    -> "C_LOGIN_RESP";
                case C_POLL          -> "C_POLL";
                case C_ACK           -> "C_ACK";
                case C_DISCONNECT    -> "C_DISCONNECT";
                case C_PING          -> "C_PING";
                case C_REGISTER      -> "C_REGISTER";
                case C_REGISTER_RESP -> "C_REGISTER_RESP";
                case C_FILTER        -> "C_FILTER";
                case C_PONG          -> "C_PONG";
                default              -> String.format("UNKNOWN(0x%02X)", type & 0xFF);
            };
        }
    }

    public static final class DiscReason {
        private DiscReason() {}
        public static final byte NORMAL           = 0x00;
        public static final byte AUTH_FAIL        = 0x01;
        public static final byte PROTOCOL         = 0x02;
        public static final byte SERVER_ERR       = 0x03;
        public static final byte REPLACED         = 0x04;
        public static final byte VERSION_MISMATCH = 0x05;
    }

    public static final byte NOTIFY_FLAG_ENCRYPTED  = 0x01;
    public static final byte NOTIFY_FLAG_COMPRESSED = 0x02;
    public static final byte PRIORITY_NORMAL   = 0x00;
    public static final byte PRIORITY_CRITICAL = 0x02;
    public static final int C_POLL_LAST_SEQ_SIZE = 8;

    /**
     * Per type payload size bounds, enforced BEFORE the payload is allocated or
     * read so a malformed frame cannot force a full MAX_PAYLOAD allocation for a
     * message that should never exceed a handful of bytes.
     */
    public static final class PayloadBounds {
        private PayloadBounds() {}

        private static final int[][] CLIENT_BOUNDS = new int[256][];

        static {
            CLIENT_BOUNDS[MsgType.C_REGISTER      & 0xFF] = new int[]{ 142,  814 };
            CLIENT_BOUNDS[MsgType.C_REGISTER_RESP & 0xFF] = new int[]{  11,  610 };
            CLIENT_BOUNDS[MsgType.C_LOGIN         & 0xFF] = new int[]{  15,   78 };
            CLIENT_BOUNDS[MsgType.C_LOGIN_RESP    & 0xFF] = new int[]{  11,  610 };
            CLIENT_BOUNDS[MsgType.C_POLL          & 0xFF] = new int[]{   0,    8 };
            CLIENT_BOUNDS[MsgType.C_ACK           & 0xFF] = new int[]{  17,   17 };
            CLIENT_BOUNDS[MsgType.C_FILTER        & 0xFF] = new int[]{   3, MAX_PAYLOAD };
            CLIENT_BOUNDS[MsgType.C_PING          & 0xFF] = new int[]{   8,    8 };
            CLIENT_BOUNDS[MsgType.C_PONG          & 0xFF] = new int[]{   8,    8 };
            CLIENT_BOUNDS[MsgType.C_DISCONNECT    & 0xFF] = new int[]{   1,    1 };
        }

        /** validates the payload length of a frame received FROM a client. */
        public static void validateClientFrame(byte type, int len) throws SGPProtocolException {
            int idx = type & 0xFF;
            if (idx >= 0x30 || CLIENT_BOUNDS[idx] == null) return;
            int min = CLIENT_BOUNDS[idx][0];
            int max = CLIENT_BOUNDS[idx][1];
            if (len < min || (max != MAX_PAYLOAD && len > max)) {
                throw new SGPProtocolException(String.format(
                    "Payload size %d out of range [%d, %d] for client type 0x%02X",
                    len, min, max, idx));
            }
        }
    }

    /**
     * Reads one frame, rejecting a non-zero reserved byte rather than silently
     * misparsing a future-incompatible frame.
     */
    public static Frame readFrame(DataInputStream in) throws IOException, SGPProtocolException {
        byte[] header = new byte[HEADER_SIZE];
        in.readFully(header);

        if (header[0] != MAGIC) {
            throw new SGPProtocolException(String.format("Bad magic: 0x%02X", header[0] & 0xFF));
        }
        if (header[1] != VERSION) {
            throw new SGPProtocolException(String.format("Unsupported version: 0x%02X", header[1] & 0xFF));
        }
        if (header[3] != 0x00) {
            throw new SGPProtocolException(String.format("Non-zero reserved byte: 0x%02X", header[3] & 0xFF));
        }

        byte type = header[2];

        int payloadLen = ((header[4] & 0xFF) << 24)
                | ((header[5] & 0xFF) << 16)
                | ((header[6] & 0xFF) <<  8)
                |  (header[7] & 0xFF);

        if (payloadLen < 0 || payloadLen > MAX_PAYLOAD) {
            throw new SGPProtocolException("Payload out of range: " + payloadLen);
        }

        PayloadBounds.validateClientFrame(type, payloadLen);

        byte[] payload = new byte[payloadLen];
        if (payloadLen > 0) in.readFully(payload);

        return new Frame(type, payload);
    }

    /** callers should check for size, this is here just in case */
    public static void writeFrame(OutputStream out, byte type, byte[] payload) throws IOException {
        int payloadLen = (payload == null) ? 0 : payload.length;
        if (payloadLen > MAX_PAYLOAD) {
            throw new IOException("Refusing to write oversized frame: " + payloadLen
                    + " bytes for type " + MsgType.name(type));
        }

        byte[] frame = new byte[HEADER_SIZE + payloadLen];
        frame[0] = MAGIC;
        frame[1] = VERSION;
        frame[2] = type;
        frame[3] = 0x00;

        frame[4] = (byte)((payloadLen >> 24) & 0xFF);
        frame[5] = (byte)((payloadLen >> 16) & 0xFF);
        frame[6] = (byte)((payloadLen >>  8) & 0xFF);
        frame[7] = (byte)( payloadLen        & 0xFF);

        if (payloadLen > 0) {
            System.arraycopy(payload, 0, frame, HEADER_SIZE, payloadLen);
        }

        out.write(frame);
        out.flush();
    }

    public record Frame(byte type, byte[] payload) {
        public int payloadLen() { return payload.length; }

        public long readU32(int offset) {
            return ((payload[offset    ] & 0xFFL) << 24)
                    | ((payload[offset + 1] & 0xFFL) << 16)
                    | ((payload[offset + 2] & 0xFFL) <<  8)
                    |  (payload[offset + 3] & 0xFFL);
        }

        public int readU16(int offset) {
            return ((payload[offset    ] & 0xFF) << 8)
                    |  (payload[offset + 1] & 0xFF);
        }

        public long readI64(int offset) {
            long v = 0;
            for (int i = 0; i < 8; i++) {
                v = (v << 8) | (payload[offset + i] & 0xFFL);
            }
            return v;
        }

        public byte[] slice(int offset, int len) {
            byte[] out = new byte[len];
            System.arraycopy(payload, offset, out, 0, len);
            return out;
        }
    }

    /** Growable big-endian payload builder. */
    public static final class PayloadBuilder {

        private byte[] buf;
        private int    pos;

        public PayloadBuilder() {
            buf = new byte[64];
            pos = 0;
        }

        private void ensureCapacity(int additional) {
            if (pos + additional > buf.length) {
                int newLen = Math.max(buf.length * 2, pos + additional);
                byte[] newBuf = new byte[newLen];
                System.arraycopy(buf, 0, newBuf, 0, pos);
                buf = newBuf;
            }
        }

        public PayloadBuilder putBytes(byte[] data) {
            ensureCapacity(data.length);
            System.arraycopy(data, 0, buf, pos, data.length);
            pos += data.length;
            return this;
        }

        public PayloadBuilder putByte(byte b) {
            ensureCapacity(1);
            buf[pos++] = b;
            return this;
        }

        public PayloadBuilder putU16(int v) {
            ensureCapacity(2);
            buf[pos++] = (byte)((v >> 8) & 0xFF);
            buf[pos++] = (byte)( v       & 0xFF);
            return this;
        }

        public PayloadBuilder putU32(long v) {
            ensureCapacity(4);
            buf[pos++] = (byte)((v >> 24) & 0xFF);
            buf[pos++] = (byte)((v >> 16) & 0xFF);
            buf[pos++] = (byte)((v >>  8) & 0xFF);
            buf[pos++] = (byte)( v        & 0xFF);
            return this;
        }

        public PayloadBuilder putI64(long v) {
            ensureCapacity(8);
            for (int i = 7; i >= 0; i--) {
                buf[pos + i] = (byte)(v & 0xFF);
                v >>= 8;
            }
            pos += 8;
            return this;
        }

        public byte[] build() {
            byte[] result = new byte[pos];
            System.arraycopy(buf, 0, result, 0, pos);
            return result;
        }
    }

    public static final class SGPProtocolException extends Exception {
        public SGPProtocolException(String message) {
            super(message);
        }
    }

    /** Encodes a JSON-decoded value tree into the CT_TLVSTRUCT wire format*/
    public static byte[] encodeStructuredTlv(Object value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeStructuredTlv(out, value);
        return out.toByteArray();
    }

    private static void writeStructuredTlv(ByteArrayOutputStream out, Object value) {
        if (value instanceof Map<?, ?> map) {
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                byte[] keyBytes = String.valueOf(e.getKey()).getBytes(StandardCharsets.UTF_8);
                writeVarint(inner, keyBytes.length);
                inner.writeBytes(keyBytes);
                writeStructuredTlv(inner, e.getValue());
            }
            byte[] innerBytes = inner.toByteArray();
            out.write(0x01);
            writeVarint(out, innerBytes.length);
            out.writeBytes(innerBytes);
        } else if (value instanceof List<?> list) {
            ByteArrayOutputStream inner = new ByteArrayOutputStream();
            for (Object item : list) writeStructuredTlv(inner, item);
            byte[] innerBytes = inner.toByteArray();
            out.write(0x02);
            writeVarint(out, innerBytes.length);
            out.writeBytes(innerBytes);
        } else if (value instanceof String s) {
            byte[] strBytes = s.getBytes(StandardCharsets.UTF_8);
            out.write(0x03);
            writeVarint(out, strBytes.length);
            out.writeBytes(strBytes);
        } else if (value instanceof Boolean b) {
            out.write(0x06);
            out.write(b ? 0x01 : 0x00);
        } else if (value == null) {
            out.write(0x07);
        } else if (value instanceof Number n) {
            Long integral = integralValue(n);
            if (integral != null) {
                out.write(0x04);
                writeVarint(out, (integral << 1) ^ (integral >> 63));
            } else {
                out.write(0x05);
                long bits = Double.doubleToLongBits(n.doubleValue());
                for (int shift = 56; shift >= 0; shift -= 8) out.write((int) (bits >>> shift));
            }
        } else {
            throw new IllegalArgumentException("Unsupported type for structured TLV: " + value.getClass());
        }
    }

    private static Long integralValue(Number n) {
        if (n instanceof Integer || n instanceof Long || n instanceof Short || n instanceof Byte) {
            return n.longValue();
        }
        if (n instanceof BigInteger bi) {
            return bi.bitLength() < 64 ? bi.longValue() : null;
        }
        return null;
    }

    private static void writeVarint(ByteArrayOutputStream out, long v) {
        while ((v & ~0x7FL) != 0) {
            out.write((int) ((v & 0x7F) | 0x80));
            v >>>= 7;
        }
        out.write((int) v);
    }
}

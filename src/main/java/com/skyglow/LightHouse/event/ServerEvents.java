package com.skyglow.LightHouse.event;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

public final class ServerEvents {

    private static final Logger log = LoggerFactory.getLogger(ServerEvents.class);

    private final List<ServerListener> listeners = new CopyOnWriteArrayList<>();

    public void subscribe(ServerListener listener) {
        listeners.add(listener);
    }

    public void ack(byte[] msgId, int status, long atMs) {
        publish(l -> l.onAck(msgId, status, atMs));
    }

    public void deviceConnected(String deviceAddress, long atMs) {
        publish(l -> l.onDeviceConnected(deviceAddress, atMs));
    }

    public void deviceDisconnected(String deviceAddress, long atMs) {
        publish(l -> l.onDeviceDisconnected(deviceAddress, atMs));
    }

    /** a listener that throws is logged and skipped */
    private void publish(Consumer<ServerListener> call) {
        for (ServerListener l : listeners) {
            try {
                call.accept(l);
            } catch (RuntimeException e) {
                log.warn("Server listener {} threw: {}", l.getClass().getSimpleName(), e.toString());
            }
        }
    }
}

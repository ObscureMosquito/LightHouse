package com.skyglow.LightHouse.event;

/**
 * Observes the connection lifecycle without the core knowing who is listening.
 * Called on the connection's virtual thread, so implementations must not block.
 */
public interface ServerListener {

    default void onAck(byte[] msgId, int status, long atMs) {}

    default void onDeviceConnected(String deviceAddress, long atMs) {}

    default void onDeviceDisconnected(String deviceAddress, long atMs) {}
}

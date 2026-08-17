package com.skyglow.LightHouse.http;

import com.sun.net.httpserver.HttpHandler;

/**
 * Where an {@link HttpModule} publishes its endpoints. Method matching and the
 * loopback gate are applied by the registry, not by the handlers.
 */
public interface RouteRegistry {

    void get(String path, HttpHandler handler);

    void post(String path, HttpHandler handler);

    /** for admin stuff */
    RouteRegistry loopbackOnly();
}

package com.skyglow.LightHouse.http;

/**
 * A pluggable group of HTTP endpoints, implementations need a public no-argument constructor.
 */
public interface HttpModule {

    String name();

    /** called once before the server accepts requests. Throwing aborts startup. */
    void register(RouteRegistry routes, ModuleContext ctx) throws Exception;

    default void shutdown() {}
}

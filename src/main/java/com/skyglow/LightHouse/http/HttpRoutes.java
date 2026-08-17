package com.skyglow.LightHouse.http;

import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * {@link RouteRegistry} backed by one {@link HttpServer} context per route,
 * wrapping each handler with exact path matching, method matching, 
 * the optional loopback gate, and a 500 catch-all.
 */
final class HttpRoutes implements RouteRegistry {

    private static final Logger log = LoggerFactory.getLogger(HttpRoutes.class);

    private final HttpServer server;
    private final boolean    loopbackOnly;

    HttpRoutes(HttpServer server) { this(server, false); }

    private HttpRoutes(HttpServer server, boolean loopbackOnly) {
        this.server       = server;
        this.loopbackOnly = loopbackOnly;
    }

    @Override
    public RouteRegistry loopbackOnly() {
        return loopbackOnly ? this : new HttpRoutes(server, true);
    }

    @Override
    public void get(String path, HttpHandler handler) { register(path, "GET", handler); }

    @Override
    public void post(String path, HttpHandler handler) { register(path, "POST", handler); }

    private void register(String path, String method, HttpHandler handler) {
        server.createContext(path, ex -> {
            try {
                if (!path.equals(normalize(ex.getRequestURI().getPath()))) {
                    Http.text(ex, 404, "Not Found");
                    return;
                }
                if (!method.equals(ex.getRequestMethod())) {
                    ex.getResponseHeaders().set("Allow", method);
                    Http.text(ex, 405, "Method Not Allowed");
                    return;
                }
                if (loopbackOnly && !Http.isLoopback(ex)) {
                    Http.text(ex, 403, "Forbidden: localhost only");
                    return;
                }
                handler.handle(ex);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                log.error("Unhandled error in {} {}: {}", method, path, e.getMessage(), e);
                Http.text(ex, 500, "Internal Server Error");
            } finally {
                ex.close();
            }
        });
    }

    /** Drops one trailing slash so /health/ resolves to the /health route. */
    private static String normalize(String path) {
        return (path.length() > 1 && path.endsWith("/")) ? path.substring(0, path.length() - 1) : path;
    }
}

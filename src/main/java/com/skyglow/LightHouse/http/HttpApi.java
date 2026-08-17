package com.skyglow.LightHouse.http;

import com.skyglow.LightHouse.config.ServerConfig;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.event.ServerEvents;
import com.skyglow.LightHouse.notify.NotificationService;
import com.skyglow.LightHouse.router.Router;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;
import java.util.concurrent.Executors;

/** Hosts the HTTP server and the {@link HttpModule}s published on it. */
public final class HttpApi {

    private static final Logger log = LoggerFactory.getLogger(HttpApi.class);

    private final HttpServer       httpServer;
    private final List<HttpModule> modules = new ArrayList<>();

    public HttpApi(ServerConfig config, Database db, Router router,
                   NotificationService notifications, ServerEvents events) throws IOException {

        httpServer = HttpServer.create(new InetSocketAddress(config.httpBind(), config.httpPort()), 64);
        httpServer.setExecutor(Executors.newVirtualThreadPerTaskExecutor());

        ModuleContext ctx    = new ModuleContext(config, db, router, notifications, events);
        RouteRegistry routes = new HttpRoutes(httpServer);

        load(new PublicApiModule(), routes, ctx);
        for (HttpModule module : discover()) load(module, routes, ctx);
    }

    /** A broken service descriptor is only logged */
    private static List<HttpModule> discover() {
        List<HttpModule> found = new ArrayList<>();
        try {
            for (HttpModule m : ServiceLoader.load(HttpModule.class)) found.add(m);
        } catch (ServiceConfigurationError e) {
            log.error("Failed to load optional HTTP modules: {}", e.getMessage(), e);
        }
        return found;
    }

    /** A module that fails to register aborts startup */
    private void load(HttpModule module, RouteRegistry routes, ModuleContext ctx) {
        try {
            module.register(routes, ctx);
            modules.add(module);
            log.info("HTTP module registered: {}", module.name());
        } catch (Exception e) {
            throw new IllegalStateException("HTTP module '" + module.name() + "' failed to register", e);
        }
    }

    public void start() {
        httpServer.start();
        log.info("HTTP API listening on {}:{} with {} module(s)",
                httpServer.getAddress().getHostString(), httpServer.getAddress().getPort(), modules.size());
    }

    public void stop() {
        for (HttpModule m : modules) {
            try { m.shutdown(); }
            catch (RuntimeException e) { log.warn("Module {} shutdown error: {}", m.name(), e.toString()); }
        }
        httpServer.stop(2);
        log.info("HTTP API stopped");
    }
}

package com.skyglow.LightHouse;

import com.skyglow.LightHouse.config.ServerConfig;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.event.ServerEvents;
import com.skyglow.LightHouse.http.HttpApi;
import com.skyglow.LightHouse.notify.NotificationService;
import com.skyglow.LightHouse.router.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private static final long PURGE_INTERVAL_MS = 5 * 60 * 1000L;

    public static void main(String[] args) throws Exception {
        log.info("Skyglow LightHouse starting: SGP/2");

        ServerConfig config = ServerConfig.fromEnv();

        Database db = new Database(config.dbUrl(), config.dbUser(), config.dbPass());
        db.initSchema();

        Router              router        = new Router();
        ServerEvents        events        = new ServerEvents();
        NotificationService notifications = new NotificationService(db, router);

        HttpApi httpApi = new HttpApi(config, db, router, notifications, events);
        httpApi.start();

        SGPServer[] serverRef = new SGPServer[1];
        Runtime.getRuntime().addShutdownHook(Thread.ofVirtual().unstarted(() -> {
            log.info("Shutdown signal received");
            if (serverRef[0] != null) serverRef[0].stop();
            httpApi.stop();
            db.close();
            log.info("Shutdown complete");
        }));

        startExpiryPurge(db);

        SGPServer tcpServer = new SGPServer(config, db, router, events);
        serverRef[0] = tcpServer;

        log.info("Server ready. TCP:{} HTTP:{}:{}", config.tcpPort(), config.httpBind(), config.httpPort());
        tcpServer.start();
    }

    private static void startExpiryPurge(Database db) {
        Thread.ofVirtual().name("expiry-purge").start(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    int deleted = db.purgeExpiredMessages();
                    if (deleted > 0) log.info("Purged {} expired queued message(s)", deleted);
                } catch (Exception e) {
                    log.error("Expiry purge error: {}", e.getMessage(), e);
                }
                try {
                    Thread.sleep(PURGE_INTERVAL_MS);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        });
    }
}

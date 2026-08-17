package com.skyglow.LightHouse.http;

import com.skyglow.LightHouse.config.ServerConfig;
import com.skyglow.LightHouse.db.Database;
import com.skyglow.LightHouse.event.ServerEvents;
import com.skyglow.LightHouse.notify.NotificationService;
import com.skyglow.LightHouse.router.Router;

/** The core services an {@link HttpModule} is given. Modules never build their own. */
public record ModuleContext(
        ServerConfig        config,
        Database            db,
        Router              router,
        NotificationService notifications,
        ServerEvents        events
) {}

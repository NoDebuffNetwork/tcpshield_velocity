package pvp.garden.tcpshield;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.proxy.ProxyServer;
import lombok.Getter;
import pvp.garden.tcpshield.listener.HandshakeListener;
import pvp.garden.tcpshield.util.Signing;

import javax.inject.Inject;
import java.util.logging.Logger;

@Getter
@Plugin(
        id = "tcpshield",
        name = "TCPShield",
        version = "1.0-SNAPSHOT",
        description = "A Velocity plugin that parses client IP addresses passed from the TCPShield network."
)
public class TCPShieldPlugin {
    private final ProxyServer server;
    private final Logger logger;

    @Inject
    public TCPShieldPlugin(ProxyServer server, Logger logger) {
        this.server = server;
        this.logger = logger;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        try {
            Signing.initialize();
        } catch (Exception e) {
            e.printStackTrace();
        }

        server.getEventManager().register(this, new HandshakeListener(this));
    }
}
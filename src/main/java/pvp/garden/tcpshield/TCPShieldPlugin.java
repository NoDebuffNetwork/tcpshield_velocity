package pvp.garden.tcpshield;

import com.google.common.io.ByteStreams;
import com.moandjiezana.toml.Toml;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import lombok.Getter;
import pvp.garden.tcpshield.listener.HandshakeListener;
import pvp.garden.tcpshield.util.Signing;

import javax.inject.Inject;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
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
    private final Path path;

    private boolean onlyAllowProxyConnections;

    @Inject
    public TCPShieldPlugin(ProxyServer server, Logger logger, @DataDirectory Path path) {
        this.server = server;
        this.logger = logger;
        this.path = path;
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        loadConfig();

        try {
            Signing.initialize();
        } catch (Exception e) {
            e.printStackTrace();
        }

        server.getEventManager().register(this, new HandshakeListener(this));
    }

    private void loadConfig() {
        File directory = path.toFile();

        if (!directory.exists()) {
            directory.mkdirs();
        }

        File config = new File(directory, "config.toml");

        if (!config.exists()) {
            try (InputStream in = getClass().getClassLoader()
                    .getResourceAsStream("config.toml");
                 OutputStream out = new FileOutputStream(config)) {
                ByteStreams.copy(in, out);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        Toml toml = new Toml().read(config);
        onlyAllowProxyConnections = toml.getBoolean("only-allow-proxy-connections", true);
    }
}
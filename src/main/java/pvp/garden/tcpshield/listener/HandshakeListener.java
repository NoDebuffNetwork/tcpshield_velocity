package pvp.garden.tcpshield.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.ConnectionHandshakeEvent;
import lombok.RequiredArgsConstructor;
import pvp.garden.tcpshield.TCPShieldPlugin;
import pvp.garden.tcpshield.util.Signing;
import pvp.garden.tcpshield.util.VelocityReflection;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class HandshakeListener {
    private final TCPShieldPlugin plugin;

    @Subscribe
    public void onConnectionHandshake(ConnectionHandshakeEvent event) {
        boolean isProxyConnection = false;

        try {
            String raw = VelocityReflection.getHostname(event.getConnection());

            if (raw.contains("//")) {
                String[] payload = raw.split("///");

                if (payload.length >= 4) {
                    String hostname = payload[0];
                    String ipData = payload[1];
                    int timestamp = Integer.parseInt(payload[2]);
                    String signature = payload[3];

                    String[] hostnameParts = ipData.split(":");
                    String host = hostnameParts[0];
                    int port = Integer.parseInt(hostnameParts[1]);

                    String reconstructedPayload = hostname + "///" + host + ":" + port + "///" + timestamp;

                    if (!Signing.verify(reconstructedPayload.getBytes(StandardCharsets.UTF_8), signature)) {
                        throw new Exception("Couldn't verify signature.");
                    }

                    isProxyConnection = true;

                    VelocityReflection.setConnectionFields(
                            event.getConnection(),
                            host,
                            port,
                            hostname,
                            new InetSocketAddress(host, port)
                    );
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (!isProxyConnection) {
                plugin.getLogger().warning("Disconnecting " + event.getConnection().getRemoteAddress().getHostName()
                        + " because no proxy info was received.");

                try {
                    VelocityReflection.forceDisconnect(event.getConnection());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}

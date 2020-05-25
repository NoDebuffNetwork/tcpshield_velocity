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
                String[] payload = raw.split("///", 3);

                if (payload.length >= 3) {
                    String hostname = payload[0];
                    String ipData = payload[1];
                    String[] ts_sig = payload[2].split("///", 2);

                    if (ts_sig.length >= 2) {
                        int timestamp = Integer.parseInt(ts_sig[0]);
                        String signature = ts_sig[1];

                        String[] hostnameParts = ipData.split(":");
                        String host = hostnameParts[0];
                        int port = Integer.parseInt(hostnameParts[1]);

                        String reconstructedPayload = hostname + "///" + host + ":" + port + "///" + timestamp;

                        if (signature.contains("%%%")) {
                            signature = signature.split("%%%", 2)[0];
                        }

                        if (!Signing.verify(reconstructedPayload.getBytes(StandardCharsets.UTF_8), signature)) {
                            throw new Exception("Couldn't verify signature.");
                        }

                        long currentTime = System.currentTimeMillis() / 1000;

                        if(!(timestamp >= (currentTime - 2) && timestamp <= (currentTime + 2))) {
                            /*if(this.debugMode) {
                                getLogger().warning("Current time: " + currentTime + ", Timestamp Time: "  + timestamp);
                            }*/
                            throw new Exception("Invalid signature timestamp, please check system's local clock if error persists.");
                        }

                        hostname = hostname.replace("%%%", "\u0000");
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
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (plugin.isOnlyAllowProxyConnections() && !isProxyConnection) {
                plugin.getLogger().warning("Disconnecting " + event.getConnection().getRemoteAddress().getHostName()
                        + " because no proxy info was received and only-allow-proxy-connections is enabled.");

                try {
                    VelocityReflection.forceDisconnect(event.getConnection());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }
    }
}

package pvp.garden.tcpshield.util;

import com.velocitypowered.api.proxy.InboundConnection;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;

public class VelocityReflection {
    private static Class<?> abstractChannelClass;
    private static Class<?> minecraftConnectionClass;
    private static Class<?> initialInboundConnectionClass;
    private static Class<?> handshakeClass;

    // AbstractChannel (netty)
    private static Field nettyRemoteAddressField;
    private static Field localAddressField;

    // MinecraftConnection
    private static Field connectionRemoteAddressField;
    private static Field channelField;

    private static Method closeMethod;

    // InitialInboundConnection
    private static Field handshakeField;
    private static Field connectionField;

    // Handshake
    private static Field serverAddressField;

    static {
        try {
            abstractChannelClass
                    = Class.forName("io.netty.channel.AbstractChannel");
            minecraftConnectionClass
                    = Class.forName("com.velocitypowered.proxy.connection.MinecraftConnection");
            initialInboundConnectionClass
                    = Class.forName("com.velocitypowered.proxy.connection.client.InitialInboundConnection");
            handshakeClass
                    = Class.forName("com.velocitypowered.proxy.protocol.packet.Handshake");

            nettyRemoteAddressField = abstractChannelClass.getDeclaredField("remoteAddress");
            nettyRemoteAddressField.setAccessible(true);

            localAddressField = abstractChannelClass.getDeclaredField("localAddress");
            localAddressField.setAccessible(true);

            connectionRemoteAddressField = minecraftConnectionClass.getDeclaredField("remoteAddress");
            connectionRemoteAddressField.setAccessible(true);

            channelField = minecraftConnectionClass.getDeclaredField("channel");
            channelField.setAccessible(true);

            closeMethod = minecraftConnectionClass.getDeclaredMethod("close");

            handshakeField = initialInboundConnectionClass.getDeclaredField("handshake");
            handshakeField.setAccessible(true);

            connectionField = initialInboundConnectionClass.getDeclaredField("connection");
            connectionField.setAccessible(true);

            serverAddressField = handshakeClass.getDeclaredField("serverAddress");
            serverAddressField.setAccessible(true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static Object getHandshake(InboundConnection inbound) throws IllegalAccessException {
        return handshakeField.get(inbound);
    }

    public static Object getConnection(InboundConnection inbound) throws IllegalAccessException {
        return connectionField.get(inbound);
    }

    public static Object getChannel(Object minecraftConnection) throws IllegalAccessException {
        return channelField.get(minecraftConnection);
    }

    public static String getHostname(InboundConnection inbound) throws IllegalAccessException {
        return (String) serverAddressField.get(getHandshake(inbound));
    }

    public static void forceDisconnect(InboundConnection inbound) throws IllegalAccessException, InvocationTargetException {
        Object connection = getConnection(inbound);
        closeMethod.invoke(connection);
    }

    public static void setConnectionFields(InboundConnection inbound,
                                           String host,
                                           int port,
                                           String hostname,
                                           InetSocketAddress remoteAddress) throws IllegalAccessException {
        Object handshake = getHandshake(inbound);
        Object connection = getConnection(inbound);
        Object channel = getChannel(connection);

        nettyRemoteAddressField.set(channel, remoteAddress);
        localAddressField.set(channel, remoteAddress);

        InetSocketAddress virtualHost = new InetSocketAddress(host, port);

        connectionRemoteAddressField.set(connection, virtualHost);
        serverAddressField.set(handshake, hostname);
    }
}

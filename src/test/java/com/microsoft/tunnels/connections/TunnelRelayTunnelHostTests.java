// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.connections.ssh.SshChannel;
import com.microsoft.tunnels.connections.ssh.SshData;
import com.microsoft.tunnels.contracts.Tunnel;
import com.microsoft.tunnels.contracts.TunnelConnectionMode;
import com.microsoft.tunnels.contracts.TunnelEndpoint;
import com.microsoft.tunnels.contracts.TunnelRelayTunnelEndpoint;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * End-to-end tests of {@link TunnelRelayTunnelHost} against an in-process relay, including
 * the existing {@link TunnelRelayTunnelClient} connecting through the relay (V1 sessions).
 */
public class TunnelRelayTunnelHostTests {
  private static final int TIMEOUT_SECONDS = 20;

  private EchoServer echo;
  private EchoServer echo2;
  private FakeRelay relay;
  private TunnelRelayTunnelHost host;
  private TunnelRelayTunnelClient client;

  /** A TCP server that echoes everything it receives. */
  static final class EchoServer implements AutoCloseable {
    final ServerSocket serverSocket;

    EchoServer() throws IOException {
      serverSocket = new ServerSocket(0, 50, java.net.InetAddress.getLoopbackAddress());
      Thread thread = new Thread(() -> {
        while (!serverSocket.isClosed()) {
          try {
            Socket socket = serverSocket.accept();
            Thread worker = new Thread(() -> {
              try (socket) {
                socket.getInputStream().transferTo(socket.getOutputStream());
              } catch (IOException e) {
                // Connection ended.
              }
            });
            worker.setDaemon(true);
            worker.start();
          } catch (IOException e) {
            return;
          }
        }
      });
      thread.setDaemon(true);
      thread.start();
    }

    int port() {
      return serverSocket.getLocalPort();
    }

    @Override
    public void close() throws IOException {
      serverSocket.close();
    }
  }

  @Before
  public void setUp() throws IOException {
    echo = new EchoServer();
    echo2 = new EchoServer();
  }

  @After
  public void tearDown() throws IOException {
    if (client != null) {
      client.stop();
    }
    if (host != null) {
      host.stop();
    }
    if (relay != null) {
      relay.close();
    }
    echo.close();
    echo2.close();
  }

  private FakeManagementClient startHost(String... relayProtocols) throws Exception {
    relay = new FakeRelay(relayProtocols);
    FakeManagementClient management = new FakeManagementClient(relay.hostUri(), echo.port());
    host = new TunnelRelayTunnelHost(management);
    host.setReconnectEnabled(false);
    host.connectAsync(FakeManagementClient.tunnelReference())
        .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    relay.hostSession.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    return management;
  }

  private static String readChannel(SshChannel channel, int expectedLength) throws Exception {
    ByteArrayOutputStream received = new ByteArrayOutputStream();
    CompletableFuture<String> done = new CompletableFuture<>();
    channel.start(data -> {
      received.write(data, 0, data.length);
      if (received.size() >= expectedLength) {
        done.complete(received.toString(StandardCharsets.UTF_8.name()));
      }
    });
    return done.get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
  }

  private static String echoThroughSocket(int port, String message) throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(TIMEOUT_SECONDS * 1000);
      OutputStream output = socket.getOutputStream();
      output.write(message.getBytes(StandardCharsets.UTF_8));
      output.flush();
      InputStream input = socket.getInputStream();
      byte[] buffer = new byte[message.length()];
      int offset = 0;
      while (offset < buffer.length) {
        int count = input.read(buffer, offset, buffer.length - offset);
        if (count < 0) {
          break;
        }
        offset += count;
      }
      return new String(buffer, 0, offset, StandardCharsets.UTF_8);
    }
  }

  @Test
  public void v2HostForwardsPortsAndRelayConnections() throws Exception {
    FakeManagementClient management = startHost(
        TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL_V2,
        TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL);

    Assert.assertEquals(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL_V2,
        host.getConnectionProtocol());
    Assert.assertEquals("tunnel " + FakeManagementClient.HOST_TOKEN,
        relay.hostAuthorizationHeaders.get(0));

    // The endpoint was registered with the host's public key.
    TunnelEndpoint endpoint = management.registeredEndpoints.get(0);
    Assert.assertEquals(TunnelConnectionMode.TunnelRelay, endpoint.connectionMode);
    Assert.assertEquals(host.getHostId(), endpoint.hostId);
    Assert.assertEquals(1, endpoint.hostPublicKeys.length);

    // The host forwarded the tunnel port on the relay session, including its access token.
    Assert.assertEquals(Integer.valueOf(echo.port()),
        relay.forwardedPorts.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    Assert.assertEquals(FakeManagementClient.HOST_TOKEN, relay.forwardTokens.get(0));

    // A relay connection to the port reaches the local server.
    CompletableFuture<SshData.Reader> confirmation = new CompletableFuture<>();
    SshChannel channel = relay.openForwardedChannel(echo.port(), confirmation)
        .get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    Assert.assertFalse("E2E encryption should be reported as disabled",
        confirmation.get().readBoolean());
    channel.write("hello tunnel".getBytes(StandardCharsets.UTF_8));
    Assert.assertEquals("hello tunnel", readChannel(channel, "hello tunnel".length()));
    channel.close();

    // Stopping the host deletes its endpoint.
    host.stop();
    Assert.assertEquals(host.getEndpointId(), management.deletedEndpoints.get(0));
  }

  @Test
  public void v2HostRejectsConnectionsToPortsNotOnTheTunnel() throws Exception {
    startHost(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL_V2);
    try {
      relay.openForwardedChannel(echo2.port(), null).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
      Assert.fail("Expected the channel open to be rejected.");
    } catch (ExecutionException e) {
      Assert.assertTrue(e.getCause().getMessage().contains("not forwarded"));
    }
  }

  @Test
  public void v2HostRefreshesPortsWhenRequestedByTheRelay() throws Exception {
    FakeManagementClient management = startHost(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL_V2);
    Assert.assertEquals(Integer.valueOf(echo.port()),
        relay.forwardedPorts.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS));

    management.addPort(echo2.port());
    Assert.assertNotNull(relay.hostSession.get().request("RefreshPorts", null)
        .get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
    Assert.assertEquals(Integer.valueOf(echo2.port()),
        relay.forwardedPorts.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS));

    management.removePort(echo.port());
    host.refreshPortsAsync().get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    Assert.assertEquals(Integer.valueOf(echo.port()),
        relay.cancelledPorts.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS));
  }

  @Test
  public void javaClientConnectsToV1Host() throws Exception {
    startHost(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL);
    Assert.assertEquals(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL,
        host.getConnectionProtocol());
    runClientThroughRelay();
  }

  @Test
  public void javaClientConnectsToV2Host() throws Exception {
    // V2 hosts also accept V1 client sessions, which is how SDK clients connect.
    startHost(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL_V2);
    runClientThroughRelay();
  }

  private void runClientThroughRelay() throws Exception {
    FakeManagementClient management =
        (FakeManagementClient) getManagementClient();
    BlockingQueue<ForwardedPort> added = new LinkedBlockingQueue<>();
    client = new TunnelRelayTunnelClient();
    client.getForwardedPorts().addListener(new ForwardedPortEventListener() {
      @Override
      public void onForwardedPortAdded(ForwardedPort port) {
        added.add(port);
      }
    });

    Tunnel tunnel = FakeManagementClient.tunnelReference();
    tunnel.accessTokens = Map.of("connect", "connect-token");
    TunnelRelayTunnelEndpoint endpoint = new TunnelRelayTunnelEndpoint();
    endpoint.connectionMode = TunnelConnectionMode.TunnelRelay;
    endpoint.hostId = host.getHostId();
    endpoint.clientRelayUri = relay.clientUri();
    // The client verifies the host key against the key the host published.
    endpoint.hostPublicKeys = management.registeredEndpoints.get(0).hostPublicKeys;
    tunnel.endpoints = new TunnelEndpoint[] {endpoint};
    client.connectAsync(tunnel).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);

    // The host forwards the tunnel port to the client. The port is in use on this machine
    // (by the echo server), so the client binds a different local port.
    ForwardedPort forwarded = added.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    Assert.assertNotNull("The host should forward the port to the client.", forwarded);
    Assert.assertEquals(echo.port(), forwarded.getRemotePort());
    Assert.assertNotEquals(echo.port(), forwarded.getLocalPort());
    Assert.assertEquals("ping through the tunnel",
        echoThroughSocket(forwarded.getLocalPort(), "ping through the tunnel"));

    // A port added through the management API is forwarded after the client refreshes.
    management.addPort(echo2.port());
    client.refreshPortsAsync().get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    ForwardedPort second = added.poll(TIMEOUT_SECONDS, TimeUnit.SECONDS);
    Assert.assertNotNull("The new port should be forwarded after a refresh.", second);
    Assert.assertEquals(echo2.port(), second.getRemotePort());
    Assert.assertEquals("second port",
        echoThroughSocket(second.getLocalPort(), "second port"));
  }

  @Test
  public void javaClientRejectsUnexpectedHostKey() throws Exception {
    startHost(TunnelRelayTunnelHost.WEBSOCKET_SUBPROTOCOL_V2);
    client = new TunnelRelayTunnelClient();
    Tunnel tunnel = FakeManagementClient.tunnelReference();
    tunnel.accessTokens = Map.of("connect", "connect-token");
    TunnelRelayTunnelEndpoint endpoint = new TunnelRelayTunnelEndpoint();
    endpoint.connectionMode = TunnelConnectionMode.TunnelRelay;
    endpoint.hostId = host.getHostId();
    endpoint.clientRelayUri = relay.clientUri();
    endpoint.hostPublicKeys = new String[] {TunnelRelayTunnelHost.encodePublicKey(
        java.security.KeyPairGenerator.getInstance("RSA").generateKeyPair())};
    tunnel.endpoints = new TunnelEndpoint[] {endpoint};
    try {
      client.connectAsync(tunnel).get(TIMEOUT_SECONDS, TimeUnit.SECONDS);
      Assert.fail("Expected host key verification to fail.");
    } catch (ExecutionException e) {
      Assert.assertTrue(e.getCause() instanceof TunnelConnectionException);
    }
  }

  private Object getManagementClient() throws Exception {
    java.lang.reflect.Field field =
        TunnelRelayTunnelHost.class.getDeclaredField("managementClient");
    field.setAccessible(true);
    return field.get(host);
  }
}

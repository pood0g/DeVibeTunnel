// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.connections.ssh.NoSecuritySshSession;
import com.microsoft.tunnels.connections.ssh.NoSecuritySshSession.ChannelOpenResult;
import com.microsoft.tunnels.connections.ssh.SshChannel;
import com.microsoft.tunnels.connections.ssh.SshData;
import com.microsoft.tunnels.connections.ssh.SshMessages;
import com.microsoft.tunnels.contracts.Tunnel;
import com.microsoft.tunnels.contracts.TunnelAccessScopes;
import com.microsoft.tunnels.contracts.TunnelConnectionMode;
import com.microsoft.tunnels.contracts.TunnelEndpoint;
import com.microsoft.tunnels.contracts.TunnelPort;
import com.microsoft.tunnels.contracts.TunnelProtocol;
import com.microsoft.tunnels.contracts.TunnelRelayTunnelEndpoint;
import com.microsoft.tunnels.management.ITunnelManagementClient;
import com.microsoft.tunnels.management.TunnelRequestOptions;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocketHandshakeException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tunnel host implementation that accepts client connections via the tunnel relay and
 * forwards them to local TCP ports.
 *
 * <p>The host connects a websocket to the endpoint's host relay URI and runs an SSH session
 * with the "none" key exchange over it (the websocket is TLS-protected and authenticated with
 * the tunnel's host access token). Two relay protocols are supported:</p>
 * <ul>
 * <li><b>V2</b> ({@value #WEBSOCKET_SUBPROTOCOL_V2}): the host sends "tcpip-forward" for each
 * port on the relay session, and the relay opens a "forwarded-tcpip" channel for every client
 * connection, including web (HTTPS) connections to the port forwarding URIs.</li>
 * <li><b>V1</b> ({@value #WEBSOCKET_SUBPROTOCOL}): the relay opens a
 * "client-ssh-session-stream" channel for each client, carrying an end-to-end encrypted SSH
 * session in which this host is the SSH server.</li>
 * </ul>
 * <p>Both are offered (V2 preferred). V1 client sessions are also accepted on a V2 connection.
 * Set the environment variable {@code DEVTUNNELS_PROTOCOL_VERSION} to 1 or 2 to force one.</p>
 */
public class TunnelRelayTunnelHost implements TunnelHost {
  public static final String WEBSOCKET_SUBPROTOCOL = "tunnel-relay-host";
  public static final String WEBSOCKET_SUBPROTOCOL_V2 = "tunnel-relay-host-v2-dev";
  public static final String CLIENT_STREAM_CHANNEL_TYPE = "client-ssh-session-stream";

  private static final Logger logger = LoggerFactory.getLogger(TunnelRelayTunnelHost.class);
  private static final String SSH_VERSION = "DeVibeTunnel_"
      + (TunnelRelayTunnelHost.class.getPackage().getImplementationVersion() != null
          ? TunnelRelayTunnelHost.class.getPackage().getImplementationVersion() : "dev");
  private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(30);
  private static final int LOCAL_CONNECT_TIMEOUT_MS = 10_000;
  private static final Duration MAX_RECONNECT_DELAY = Duration.ofSeconds(30);
  private static final String DEFAULT_LOCAL_HOST = "127.0.0.1";

  private final ITunnelManagementClient managementClient;
  private final TunnelHostListener listener;
  private final String hostId;
  private final String endpointId;
  private final HttpClient httpClient;
  private final ExecutorService executor = Executors.newCachedThreadPool(runnable -> {
    Thread thread = new Thread(runnable, "tunnel-host");
    thread.setDaemon(true);
    return thread;
  });
  private final Set<Integer> relayForwardedPorts = ConcurrentHashMap.newKeySet();
  private final Object connectLock = new Object();

  private boolean reconnectEnabled = true;
  private String localHost = DEFAULT_LOCAL_HOST;
  private volatile Tunnel tunnel;
  private volatile KeyPair hostKey;
  private volatile String hostRelayUri;
  private volatile NoSecuritySshSession session;
  private volatile String connectionProtocol;
  private volatile ClientSessionServer clientSessionServer;
  private volatile boolean disposed;
  private volatile boolean endpointRegistered;
  private volatile int lastDisconnectReason;

  public TunnelRelayTunnelHost(ITunnelManagementClient managementClient) {
    this(managementClient, null);
  }

  /**
   * Creates a tunnel host.
   *
   * @param managementClient Management client used to register the host endpoint and to
   *                         fetch host tokens and ports.
   * @param listener         Optional listener for connection events.
   */
  public TunnelRelayTunnelHost(
      ITunnelManagementClient managementClient,
      TunnelHostListener listener) {
    if (managementClient == null) {
      throw new IllegalArgumentException("A management client is required.");
    }
    this.managementClient = managementClient;
    this.listener = listener != null ? listener : new TunnelHostListener() {
    };
    this.hostId = UUID.randomUUID().toString();
    this.endpointId = this.hostId + "-relay";
    this.httpClient = HttpClient.newBuilder().connectTimeout(CONNECT_TIMEOUT).build();
  }

  /** Whether the host reconnects automatically after losing the relay connection. */
  public void setReconnectEnabled(boolean reconnectEnabled) {
    this.reconnectEnabled = reconnectEnabled;
  }

  /** Host name or address that forwarded connections are made to. Defaults to 127.0.0.1. */
  public void setLocalHost(String localHost) {
    this.localHost = localHost != null ? localHost : DEFAULT_LOCAL_HOST;
  }

  public String getHostId() {
    return hostId;
  }

  public String getEndpointId() {
    return endpointId;
  }

  /** The negotiated relay protocol, or null if not connected. */
  public String getConnectionProtocol() {
    return connectionProtocol;
  }

  public Tunnel getTunnel() {
    return tunnel;
  }

  public boolean isConnected() {
    NoSecuritySshSession current = session;
    return current != null && !current.isClosed();
  }

  @Override
  public CompletableFuture<Void> connectAsync(Tunnel tunnel) {
    if (tunnel == null) {
      throw new IllegalArgumentException("Tunnel must not be null.");
    }
    if (this.tunnel != null) {
      throw new IllegalStateException(
          "Already connected. Use separate instances to host multiple tunnels.");
    }
    this.tunnel = tunnel;
    return CompletableFuture.runAsync(() -> {
      ensureHostToken(false);
      hostKey = generateHostKey();
      clientSessionServer = new ClientSessionServer(
          hostKey,
          this::getPortNumbers,
          this::refreshPortsAsync,
          DEFAULT_LOCAL_HOST,
          this.listener);
      registerEndpoint();
      connectRelay();
    }, executor);
  }

  private static KeyPair generateHostKey() {
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
      generator.initialize(2048);
      return generator.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new TunnelConnectionException("Failed to generate the host key.", e);
    }
  }

  private static String getAccessToken(Tunnel tunnel, String scope) {
    if (tunnel.accessTokens == null) {
      return null;
    }
    for (Map.Entry<String, String> entry : tunnel.accessTokens.entrySet()) {
      if (Arrays.asList(entry.getKey().split(" ")).contains(scope)) {
        return entry.getValue();
      }
    }
    return null;
  }

  /**
   * Ensures the tunnel has a host access token and up-to-date ports, fetching them from the
   * management service if needed (or always when {@code refresh} is true).
   */
  private void ensureHostToken(boolean refresh) {
    Tunnel current = this.tunnel;
    if (!refresh && getAccessToken(current, TunnelAccessScopes.host) != null
        && current.ports != null) {
      return;
    }
    TunnelRequestOptions options = new TunnelRequestOptions();
    options.tokenScopes = List.of(TunnelAccessScopes.host);
    options.includePorts = true;
    Tunnel fetched = managementClient.getTunnelAsync(current, options).join();
    if (fetched == null) {
      throw new TunnelConnectionException("Tunnel not found.");
    }
    String hostToken = getAccessToken(fetched, TunnelAccessScopes.host);
    if (hostToken == null) {
      throw new TunnelConnectionException(
          "Could not get a host access token for the tunnel. "
              + "Check that you are logged in and have host access to the tunnel.");
    }
    Map<String, String> tokens =
        current.accessTokens != null ? new HashMap<>(current.accessTokens) : new HashMap<>();
    tokens.put(TunnelAccessScopes.host, hostToken);
    current.accessTokens = tokens;
    current.ports = fetched.ports != null ? fetched.ports : new TunnelPort[0];
    if (current.tunnelId == null) {
      current.tunnelId = fetched.tunnelId;
    }
    if (current.clusterId == null) {
      current.clusterId = fetched.clusterId;
    }
    if (current.name == null) {
      current.name = fetched.name;
    }
    if (current.domain == null) {
      current.domain = fetched.domain;
    }
  }

  private String getHostToken() {
    return getAccessToken(tunnel, TunnelAccessScopes.host);
  }

  private void registerEndpoint() {
    TunnelRelayTunnelEndpoint endpoint = new TunnelRelayTunnelEndpoint();
    endpoint.id = endpointId;
    endpoint.hostId = hostId;
    endpoint.connectionMode = TunnelConnectionMode.TunnelRelay;
    endpoint.hostPublicKeys = new String[] {encodePublicKey(hostKey)};

    TunnelRequestOptions options = new TunnelRequestOptions();
    boolean hasSshPort = tunnel.ports != null && Arrays.stream(tunnel.ports)
        .anyMatch(p -> TunnelProtocol.ssh.equals(p.protocol));
    if (hasSshPort) {
      options.additionalQueryParameters = new HashMap<>();
      options.additionalQueryParameters.put("includeSshGatewayPublicKey", "true");
    }

    TunnelEndpoint result = managementClient
        .updateTunnelEndpointAsync(tunnel, endpoint, options).join();
    if (!(result instanceof TunnelRelayTunnelEndpoint)
        || ((TunnelRelayTunnelEndpoint) result).hostRelayUri == null) {
      throw new TunnelConnectionException(
          "The tunnel service did not return a host relay URI for the endpoint.");
    }
    hostRelayUri = ((TunnelRelayTunnelEndpoint) result).hostRelayUri;
    endpointRegistered = true;
    logger.debug("Registered host endpoint {} with relay {}", endpointId, hostRelayUri);
  }

  /** Encodes a public key as the base64 SSH wire-format blob used in hostPublicKeys. */
  static String encodePublicKey(KeyPair keyPair) {
    String entry = PublicKeyEntry.toString(keyPair.getPublic());
    return entry.split(" ")[1];
  }

  private static List<String> getSubprotocols() {
    String version = System.getenv("DEVTUNNELS_PROTOCOL_VERSION");
    if ("1".equals(version)) {
      return List.of(WEBSOCKET_SUBPROTOCOL);
    } else if ("2".equals(version)) {
      return List.of(WEBSOCKET_SUBPROTOCOL_V2);
    }
    return List.of(WEBSOCKET_SUBPROTOCOL_V2, WEBSOCKET_SUBPROTOCOL);
  }

  /**
   * Connects the relay websocket and SSH session.
   *
   * @throws RelayRejectedException if the relay rejected the websocket upgrade.
   */
  private void connectRelay() {
    synchronized (connectLock) {
      if (disposed) {
        throw new TunnelConnectionException("The host was stopped.");
      }
      logger.info("Connecting to host tunnel relay {}", hostRelayUri);
      WebSocketStream stream;
      try {
        stream = WebSocketStream.connect(
            httpClient,
            URI.create(hostRelayUri),
            getSubprotocols(),
            "tunnel " + getHostToken(),
            CONNECT_TIMEOUT).join();
      } catch (CompletionException e) {
        Throwable cause = e.getCause();
        if (cause instanceof WebSocketHandshakeException) {
          int status = ((WebSocketHandshakeException) cause).getResponse().statusCode();
          throw new RelayRejectedException(status);
        }
        throw new TunnelConnectionException(
            "Failed to connect to the tunnel relay: " + cause, cause);
      }

      String protocol = stream.getSubprotocol();
      NoSecuritySshSession newSession = new NoSecuritySshSession(
          stream.getInputStream(),
          stream.getOutputStream(),
          SSH_VERSION,
          true,
          new RelaySessionHandler());
      try {
        newSession.connect();
      } catch (IOException e) {
        stream.close();
        throw new TunnelConnectionException("Failed to start the relay SSH session.", e);
      }
      connectionProtocol = protocol;
      session = newSession;
      relayForwardedPorts.clear();
      logger.info("Host connected to relay using protocol {}", protocol);

      if (WEBSOCKET_SUBPROTOCOL_V2.equals(protocol)) {
        // In V2 the host forwards the ports on the relay session as soon as it connects.
        for (int port : getPortNumbers()) {
          forwardRelayPort(newSession, port);
        }
      }
      newSession.getClosedFuture().thenAccept(reason -> onSessionClosed(newSession, reason));
      listener.onConnected(protocol);
    }
  }

  private List<Integer> getPortNumbers() {
    Tunnel current = tunnel;
    if (current == null || current.ports == null) {
      return List.of();
    }
    return Arrays.stream(current.ports).map(p -> p.portNumber).collect(Collectors.toList());
  }

  private byte[] createPortRelayRequest(int port) {
    // PortRelayRequestMessage: a standard tcpip-forward request plus the host access token.
    return new SshData.Writer()
        .writeString(DEFAULT_LOCAL_HOST)
        .writeUint32(port)
        .writeString(getHostToken())
        .toByteArray();
  }

  private boolean forwardRelayPort(NoSecuritySshSession relaySession, int port) {
    try {
      SshData.Reader reply = relaySession.request(
          "tcpip-forward", createPortRelayRequest(port)).join();
      if (reply == null) {
        logger.warn("The relay rejected forwarding of port {}.", port);
        return false;
      }
      relayForwardedPorts.add(port);
      logger.debug("Forwarding port {} on the relay.", port);
      return true;
    } catch (CompletionException e) {
      logger.warn("Failed to forward port {}: {}", port, e.getCause().toString());
      return false;
    }
  }

  private void cancelRelayPort(NoSecuritySshSession relaySession, int port) {
    try {
      relaySession.request("cancel-tcpip-forward", createPortRelayRequest(port)).join();
    } catch (CompletionException e) {
      logger.debug("Failed to cancel forwarding of port {}: {}", port, e.getCause().toString());
    }
    relayForwardedPorts.remove(port);
  }

  private void onSessionClosed(NoSecuritySshSession closedSession, int reason) {
    if (closedSession != session) {
      return;
    }
    lastDisconnectReason = reason;
    connectionProtocol = null;
    if (disposed) {
      return;
    }
    boolean tooManyConnections = reason == SshMessages.DISCONNECT_TOO_MANY_CONNECTIONS;
    boolean reconnect = reconnectEnabled && !tooManyConnections;
    String description = tooManyConnections
        ? "Another host for this tunnel has connected. Only one host connection at a time "
            + "is supported."
        : "Relay connection closed (reason " + reason + ").";
    if (tooManyConnections) {
      logger.error(description);
    } else {
      logger.warn(description + (reconnect ? " Reconnecting..." : ""));
    }
    listener.onDisconnected(description, reconnect);
    if (reconnect) {
      executor.execute(this::reconnectLoop);
    }
  }

  private void reconnectLoop() {
    long delayMillis = 1000;
    while (!disposed) {
      try {
        Thread.sleep(delayMillis);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
      try {
        connectRelay();
        return;
      } catch (RelayRejectedException e) {
        logger.warn("Relay rejected the host connection (HTTP {}).", e.statusCode);
        try {
          if (e.statusCode == 401 || e.statusCode == 403) {
            // The host access token probably expired; get a new one.
            ensureHostToken(true);
          } else if (e.statusCode == 404) {
            registerEndpoint();
          }
        } catch (RuntimeException refreshError) {
          logger.warn("Failed to refresh the host connection: {}", refreshError.toString());
        }
      } catch (RuntimeException e) {
        logger.warn("Reconnect failed: {}", e.getMessage());
      }
      delayMillis = Math.min(delayMillis * 2, MAX_RECONNECT_DELAY.toMillis());
    }
  }

  @Override
  public CompletableFuture<Void> refreshPortsAsync() {
    return CompletableFuture.runAsync(() -> {
      Tunnel current = tunnel;
      if (current == null) {
        throw new IllegalStateException("The host is not connected.");
      }
      Collection<TunnelPort> ports = managementClient.listTunnelPortsAsync(current, null).join();
      List<Integer> previous = getPortNumbers();
      current.ports = ports != null ? ports.toArray(new TunnelPort[0]) : new TunnelPort[0];
      List<Integer> updated = getPortNumbers();

      List<Integer> added = new ArrayList<>(updated);
      added.removeAll(previous);
      List<Integer> removed = new ArrayList<>(previous);
      removed.removeAll(updated);
      logger.info("Refreshed ports: added {}, removed {}", added, removed);

      NoSecuritySshSession current2 = session;
      if (current2 != null && !current2.isClosed()
          && WEBSOCKET_SUBPROTOCOL_V2.equals(connectionProtocol)) {
        for (int port : removed) {
          cancelRelayPort(current2, port);
        }
        for (int port : updated) {
          if (!relayForwardedPorts.contains(port)) {
            forwardRelayPort(current2, port);
          }
        }
      }
      ClientSessionServer server = clientSessionServer;
      if (server != null) {
        server.updatePorts(added, removed);
      }
    }, executor);
  }

  private Socket connectLocal(int port) throws IOException {
    IOException lastError = null;
    List<String> hosts = DEFAULT_LOCAL_HOST.equals(localHost)
        ? List.of(DEFAULT_LOCAL_HOST, "::1") : List.of(localHost);
    for (String host : hosts) {
      Socket socket = new Socket();
      try {
        socket.connect(new InetSocketAddress(host, port), LOCAL_CONNECT_TIMEOUT_MS);
        socket.setTcpNoDelay(true);
        return socket;
      } catch (IOException e) {
        socket.close();
        lastError = e;
      }
    }
    throw lastError;
  }

  @Override
  public void stop() {
    if (disposed) {
      return;
    }
    disposed = true;
    NoSecuritySshSession current = session;
    if (current != null) {
      current.close(SshMessages.DISCONNECT_BY_APPLICATION, "The host is disconnecting.");
    }
    ClientSessionServer server = clientSessionServer;
    if (server != null) {
      server.close();
    }
    // If another host connected (too many connections), it has replaced this endpoint.
    if (endpointRegistered
        && lastDisconnectReason != SshMessages.DISCONNECT_TOO_MANY_CONNECTIONS) {
      try {
        managementClient.deleteTunnelEndpointsAsync(tunnel, endpointId, null).join();
      } catch (RuntimeException e) {
        logger.warn("Failed to delete the host endpoint: {}", e.toString());
      }
    }
    executor.shutdownNow();
  }

  /** Handles requests from the relay on the host SSH session. */
  private final class RelaySessionHandler implements NoSecuritySshSession.Handler {
    @Override
    public CompletableFuture<ChannelOpenResult> onChannelOpening(
        SshChannel channel, SshData.Reader extraData) {
      if (disposed) {
        return CompletableFuture.completedFuture(ChannelOpenResult.reject(
            SshMessages.OPEN_CONNECT_FAILED, "The host is disconnecting."));
      }
      switch (channel.getChannelType()) {
        case "forwarded-tcpip":
          return onForwardedTcpipChannel(channel, extraData);
        case CLIENT_STREAM_CHANNEL_TYPE:
          return CompletableFuture.completedFuture(ChannelOpenResult.accept(null, () -> {
            try {
              clientSessionServer.acceptClientSession(channel);
            } catch (Exception e) {
              logger.warn("Failed to start client SSH session: {}", e.toString());
              channel.close();
            }
          }));
        default:
          logger.warn("Rejecting unknown channel type {}", channel.getChannelType());
          return CompletableFuture.completedFuture(ChannelOpenResult.reject(
              SshMessages.OPEN_UNKNOWN_CHANNEL_TYPE,
              "Unknown channel type: " + channel.getChannelType()));
      }
    }

    private CompletableFuture<ChannelOpenResult> onForwardedTcpipChannel(
        SshChannel channel, SshData.Reader request) {
      // PortRelayConnectRequestMessage: forwarded-tcpip fields, then an access token and
      // whether the client requested end-to-end encryption.
      request.readString(); // connected address
      int port = request.readInt();
      String originatorAddress = request.readString();
      int originatorPort = request.readInt();
      boolean e2eRequested = false;
      if (request.available() > 0) {
        request.readString(); // access token
        if (request.available() > 0) {
          e2eRequested = request.readBoolean();
        }
      }
      if (!getPortNumbers().contains(port)) {
        logger.warn("Rejecting connection to port {}, which is not forwarded.", port);
        return CompletableFuture.completedFuture(ChannelOpenResult.reject(
            SshMessages.OPEN_ADMINISTRATIVELY_PROHIBITED, "Port is not forwarded."));
      }
      if (e2eRequested) {
        logger.debug("Client requested E2E encryption, which this host does not support; "
            + "continuing without it.");
      }
      // PortRelayConnectResponseMessage: the confirmation plus "E2E encryption enabled".
      byte[] response = new SshData.Writer().writeBoolean(false).toByteArray();
      String originator = originatorAddress + ":" + originatorPort;
      return CompletableFuture.supplyAsync(() -> {
        Socket socket;
        try {
          socket = connectLocal(port);
        } catch (IOException e) {
          logger.warn("Failed to connect to local port {}: {}", port, e.getMessage());
          return ChannelOpenResult.reject(
              SshMessages.OPEN_CONNECT_FAILED, "Failed to connect to local port.");
        }
        listener.onForwardedConnection(port, originator);
        return ChannelOpenResult.accept(response, () -> {
          try {
            ChannelSocketPipe.start(channel, socket);
          } catch (IOException e) {
            channel.close();
          }
        });
      }, executor);
    }

    @Override
    public CompletableFuture<byte[]> onGlobalRequest(String requestType, SshData.Reader data) {
      if (ClientSessionServer.REFRESH_PORTS_REQUEST.equals(requestType)) {
        return refreshPortsAsync().thenApply(v -> new byte[0]);
      }
      return CompletableFuture.completedFuture(null);
    }
  }

  /** Thrown when the relay rejects the websocket upgrade. */
  private static final class RelayRejectedException extends TunnelConnectionException {
    final int statusCode;

    RelayRejectedException(int statusCode) {
      super("The tunnel relay rejected the host connection: HTTP " + statusCode);
      this.statusCode = statusCode;
    }
  }
}

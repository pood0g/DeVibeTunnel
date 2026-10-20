// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.connections.ssh.SshChannel;

import java.io.IOException;
import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.IntPredicate;
import java.util.function.Supplier;

import org.apache.sshd.common.SshConstants;
import org.apache.sshd.common.channel.Channel;
import org.apache.sshd.common.channel.ChannelFactory;
import org.apache.sshd.common.channel.RequestHandler;
import org.apache.sshd.common.channel.RequestHandler.Result;
import org.apache.sshd.common.io.nio2.Nio2ServiceFactoryFactory;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.session.ConnectionService;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionListener;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.apache.sshd.server.ServerBuilder;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.auth.UserAuthNoneFactory;
import org.apache.sshd.server.forward.AcceptAllForwardingFilter;
import org.apache.sshd.server.forward.TcpForwardingFilter;
import org.apache.sshd.server.forward.TcpipServerChannel;
import org.apache.sshd.server.session.ServerSession;
import org.apache.sshd.server.session.SessionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Runs the per-client SSH server sessions of the V1 relay protocol.
 *
 * <p>In V1 the relay opens a "client-ssh-session-stream" channel on the host session for each
 * connecting client. The bytes on that channel are an end-to-end encrypted SSH session between
 * the client and the host, in which the host is the SSH server. After the client authenticates
 * (the relay already authenticated it, so "none" is accepted), the host sends "tcpip-forward"
 * requests for the tunnel ports and the client opens "forwarded-tcpip" channels for each
 * connection.</p>
 */
final class ClientSessionServer {
  static final String REFRESH_PORTS_REQUEST = "RefreshPorts";
  private static final Logger logger = LoggerFactory.getLogger(ClientSessionServer.class);
  private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);
  private static final Duration CLOSE_TIMEOUT = Duration.ofSeconds(2);

  private final SshServer server;
  private final Set<ServerSession> sessions = ConcurrentHashMap.newKeySet();
  private final Supplier<List<Integer>> ports;
  private final Supplier<CompletableFuture<Void>> refreshPorts;
  private final String loopbackHost;
  private final TunnelHostListener listener;

  /** An SSH server that is never bound to a port; sessions are created on relay channels. */
  private static final class UnboundServer extends SshServer {
    void prepare() {
      checkConfig();
      setSessionFactory(new SessionFactory(this));
    }
  }

  ClientSessionServer(
      KeyPair hostKey,
      Supplier<List<Integer>> ports,
      Supplier<CompletableFuture<Void>> refreshPorts,
      String loopbackHost,
      TunnelHostListener listener) {
    this.ports = ports;
    this.refreshPorts = refreshPorts;
    this.loopbackHost = loopbackHost;
    this.listener = listener;

    UnboundServer unbound = (UnboundServer) ServerBuilder.builder()
        .factory(UnboundServer::new)
        .build();
    unbound.setIoServiceFactoryFactory(new Nio2ServiceFactoryFactory());
    unbound.setKeyPairProvider(KeyPairProvider.wrap(hostKey));
    unbound.setUserAuthFactories(List.of(UserAuthNoneFactory.INSTANCE));
    unbound.setForwardingFilter(AcceptAllForwardingFilter.INSTANCE);
    unbound.setChannelFactories(List.of(new ForwardedTcpipFactory()));

    List<RequestHandler<ConnectionService>> globals =
        new ArrayList<>(unbound.getGlobalRequestHandlers());
    globals.add(new RefreshPortsHandler());
    unbound.setGlobalRequestHandlers(globals);

    unbound.addSessionListener(new SessionListener() {
      @Override
      public void sessionEvent(Session session, Event event) {
        if (event == Event.Authenticated && session instanceof ServerSession) {
          sessions.add((ServerSession) session);
          listener.onClientSessionChanged(true);
          CompletableFuture.runAsync(() -> forwardPorts((ServerSession) session, ports.get()));
        }
      }

      @Override
      public void sessionClosed(Session session) {
        if (sessions.remove(session)) {
          listener.onClientSessionChanged(false);
        }
      }
    });
    unbound.prepare();
    this.server = unbound;
  }

  /**
   * Starts an SSH server session on a confirmed client-session channel.
   */
  void acceptClientSession(SshChannel channel) throws Exception {
    new ChannelIoSession(channel, server.getSessionFactory()).start();
  }

  /**
   * Forwards newly added ports to, and cancels removed ports on, every client session.
   */
  void updatePorts(List<Integer> added, List<Integer> removed) {
    for (ServerSession session : sessions) {
      for (int port : removed) {
        sendForwardRequest(session, "cancel-tcpip-forward", port);
      }
      forwardPorts(session, added);
    }
  }

  private void forwardPorts(ServerSession session, List<Integer> portNumbers) {
    for (int port : portNumbers) {
      if (!sendForwardRequest(session, "tcpip-forward", port)) {
        logger.warn("Client rejected forwarding of port {}.", port);
      }
    }
  }

  private boolean sendForwardRequest(ServerSession session, String request, int port) {
    try {
      Buffer buffer = session.createBuffer(SshConstants.SSH_MSG_GLOBAL_REQUEST);
      buffer.putString(request);
      buffer.putBoolean(true);
      buffer.putString(loopbackHost);
      buffer.putInt(port);
      return session.request(request, buffer, REQUEST_TIMEOUT) != null;
    } catch (IOException e) {
      logger.debug("Failed to send {} for port {}: {}", request, port, e.toString());
      return false;
    }
  }

  void close() {
    for (ServerSession session : sessions) {
      // Wait briefly so sessions finish closing before the server's timer is shut down.
      try {
        session.close(true).await(CLOSE_TIMEOUT);
      } catch (IOException e) {
        logger.debug("Error closing client session.", e);
      }
    }
    sessions.clear();
    try {
      server.stop(true);
    } catch (IOException e) {
      logger.debug("Error stopping client session server.", e);
    }
  }

  /**
   * Handles "forwarded-tcpip" channels from clients by connecting to the local port.
   * The connected address in the open message is replaced by the loopback address, and only
   * ports that are configured on the tunnel are allowed.
   */
  private final class ForwardedTcpipFactory implements ChannelFactory {
    @Override
    public String getName() {
      return "forwarded-tcpip";
    }

    @Override
    public Channel createChannel(Session session) {
      return new LoopbackTcpipChannel(port -> ports.get().contains(port));
    }
  }

  private final class LoopbackTcpipChannel extends TcpipServerChannel {
    private final IntPredicate isAllowedPort;

    LoopbackTcpipChannel(IntPredicate isAllowedPort) {
      super(TcpForwardingFilter.Type.Direct, null);
      this.isAllowedPort = isAllowedPort;
    }

    @Override
    protected org.apache.sshd.client.future.OpenFuture doInit(Buffer buffer) {
      buffer.getString(); // connected address
      int port = buffer.getInt();
      String originatorAddress = buffer.getString();
      int originatorPort = buffer.getInt();
      if (!isAllowedPort.test(port)) {
        logger.warn("Rejecting connection to port {}, which is not forwarded.", port);
        port = 0; // Port 0 is never connectable, so the open fails.
      } else {
        listener.onForwardedConnection(port, originatorAddress + ":" + originatorPort);
      }
      Buffer rewritten = new ByteArrayBuffer();
      rewritten.putString(loopbackHost);
      rewritten.putInt(port);
      rewritten.putString(originatorAddress);
      rewritten.putInt(originatorPort);
      return super.doInit(rewritten);
    }
  }

  /**
   * Handles "RefreshPorts" requests sent by clients after ports were changed through the
   * management API. The reply is sent once the refresh has completed; replying asynchronously
   * keeps the session's message loop free to process the port-forward replies.
   */
  private final class RefreshPortsHandler implements RequestHandler<ConnectionService> {
    @Override
    public Result process(
        ConnectionService service, String request, boolean wantReply, Buffer buffer) {
      if (!REFRESH_PORTS_REQUEST.equals(request)) {
        return Result.Unsupported;
      }
      Session session = service.getSession();
      refreshPorts.get().whenComplete((result, error) -> {
        if (!wantReply) {
          return;
        }
        try {
          byte command = error == null
              ? SshConstants.SSH_MSG_REQUEST_SUCCESS : SshConstants.SSH_MSG_REQUEST_FAILURE;
          session.writePacket(session.createBuffer(command, 0));
        } catch (IOException e) {
          logger.debug("Failed to reply to RefreshPorts.", e);
        }
      });
      return Result.Replied;
    }
  }
}

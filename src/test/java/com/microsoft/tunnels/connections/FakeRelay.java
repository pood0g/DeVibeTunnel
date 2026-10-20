// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.connections.ssh.NoSecuritySshSession;
import com.microsoft.tunnels.connections.ssh.NoSecuritySshSession.ChannelOpenResult;
import com.microsoft.tunnels.connections.ssh.SshChannel;
import com.microsoft.tunnels.connections.ssh.SshData;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.websocketx.BinaryWebSocketFrame;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolConfig;
import io.netty.handler.codec.http.websocketx.WebSocketServerProtocolHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * A minimal in-process tunnel relay for tests.
 *
 * <p>Hosts connect to {@code /host} and clients to {@code /client}. The relay runs the
 * server side of the host's "none" SSH session. For V2 hosts it records port-forward requests
 * and can open "forwarded-tcpip" channels like the real relay does for web clients. For each
 * client websocket it opens a "client-ssh-session-stream" channel to the host and pipes the
 * client's bytes through it, as the real relay does for V1 client sessions.</p>
 */
final class FakeRelay implements AutoCloseable {
  final List<String> hostAuthorizationHeaders = new CopyOnWriteArrayList<>();
  final List<String> hostProtocols = new CopyOnWriteArrayList<>();
  final BlockingQueue<Integer> forwardedPorts = new LinkedBlockingQueue<>();
  final BlockingQueue<Integer> cancelledPorts = new LinkedBlockingQueue<>();
  final List<String> forwardTokens = new CopyOnWriteArrayList<>();
  final CompletableFuture<NoSecuritySshSession> hostSession = new CompletableFuture<>();

  private final EventLoopGroup group = new NioEventLoopGroup(2);
  private final ExecutorService executor = Executors.newCachedThreadPool();
  private final Channel serverChannel;

  /**
   * Starts the relay.
   *
   * @param hostSubprotocols Host subprotocols the relay supports, in preference order.
   */
  FakeRelay(String... hostSubprotocols) throws InterruptedException {
    String subprotocols = String.join(",", hostSubprotocols) + ",tunnel-relay-client";
    WebSocketServerProtocolConfig config = WebSocketServerProtocolConfig.newBuilder()
        .websocketPath("/")
        .checkStartsWith(true)
        .subprotocols(subprotocols)
        .maxFramePayloadLength(1024 * 1024)
        .build();
    serverChannel = new ServerBootstrap()
        .group(group)
        .channel(NioServerSocketChannel.class)
        .childHandler(new ChannelInitializer<SocketChannel>() {
          @Override
          protected void initChannel(SocketChannel ch) {
            ch.pipeline().addLast(new HttpServerCodec());
            ch.pipeline().addLast(new HttpObjectAggregator(65536));
            ch.pipeline().addLast(new RequestRecorder());
            ch.pipeline().addLast(new WebSocketServerProtocolHandler(config));
            ch.pipeline().addLast(new RelayHandler());
          }
        })
        .bind("127.0.0.1", 0).sync().channel();
  }

  int getPort() {
    return ((InetSocketAddress) serverChannel.localAddress()).getPort();
  }

  String hostUri() {
    return "ws://127.0.0.1:" + getPort() + "/host";
  }

  String clientUri() {
    return "ws://127.0.0.1:" + getPort() + "/client";
  }

  @Override
  public void close() {
    hostSession.thenAccept(NoSecuritySshSession::close);
    serverChannel.close();
    group.shutdownGracefully();
    executor.shutdownNow();
  }

  /** Records the Authorization header of host upgrade requests. */
  private final class RequestRecorder extends ChannelInboundHandlerAdapter {
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
      if (msg instanceof FullHttpRequest) {
        FullHttpRequest request = (FullHttpRequest) msg;
        if (request.uri().startsWith("/host")) {
          hostAuthorizationHeaders.add(request.headers().get("Authorization"));
        }
      }
      ctx.fireChannelRead(msg);
    }
  }

  /** Feeds websocket frames into an InputStream. */
  private static final class FrameInputStream extends InputStream {
    private static final byte[] END = new byte[0];
    private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private byte[] current = new byte[0];
    private int position;

    void add(byte[] data) {
      queue.add(data);
    }

    void end() {
      queue.add(END);
    }

    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      while (position >= current.length) {
        try {
          current = queue.take();
        } catch (InterruptedException e) {
          throw new IOException(e);
        }
        position = 0;
        if (current == END) {
          queue.add(END);
          current = new byte[0];
          return -1;
        }
      }
      int count = Math.min(len, current.length - position);
      System.arraycopy(current, position, b, off, count);
      position += count;
      return count;
    }
  }

  private static OutputStream frameOutput(Channel channel) {
    return new OutputStream() {
      @Override
      public void write(int b) {
        write(new byte[] {(byte) b}, 0, 1);
      }

      @Override
      public void write(byte[] b, int off, int len) {
        channel.writeAndFlush(new BinaryWebSocketFrame(Unpooled.copiedBuffer(b, off, len)));
      }

      @Override
      public void close() {
        channel.close();
      }
    };
  }

  private static byte[] toBytes(ByteBuf content) {
    byte[] bytes = new byte[content.readableBytes()];
    content.readBytes(bytes);
    return bytes;
  }

  private final class RelayHandler extends ChannelInboundHandlerAdapter {
    private FrameInputStream input;
    private ExecutorService clientWriter;
    private CompletableFuture<SshChannel> clientChannel;

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object event) throws Exception {
      if (!(event instanceof WebSocketServerProtocolHandler.HandshakeComplete)) {
        super.userEventTriggered(ctx, event);
        return;
      }
      WebSocketServerProtocolHandler.HandshakeComplete handshake =
          (WebSocketServerProtocolHandler.HandshakeComplete) event;
      if (handshake.requestUri().startsWith("/host")) {
        startHostSession(ctx.channel(), handshake.selectedSubprotocol());
      } else {
        startClientPipe(ctx.channel());
      }
    }

    private void startHostSession(Channel channel, String protocol) {
      hostProtocols.add(protocol);
      input = new FrameInputStream();
      NoSecuritySshSession session = new NoSecuritySshSession(
          input, frameOutput(channel), "FakeRelay_1.0", false, new HostSessionHandler());
      executor.execute(() -> {
        try {
          session.connect();
          hostSession.complete(session);
        } catch (IOException e) {
          hostSession.completeExceptionally(e);
        }
      });
    }

    private void startClientPipe(Channel channel) {
      clientWriter = Executors.newSingleThreadExecutor();
      clientChannel = hostSession.thenCompose(session ->
          session.openChannel(TunnelRelayTunnelHost.CLIENT_STREAM_CHANNEL_TYPE, null, null));
      clientChannel.thenAccept(sshChannel -> sshChannel.start(new SshChannel.Listener() {
        @Override
        public void onData(byte[] data) {
          channel.writeAndFlush(new BinaryWebSocketFrame(Unpooled.wrappedBuffer(data)));
        }

        @Override
        public void onClosed() {
          channel.close();
        }
      }));
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
      if (msg instanceof BinaryWebSocketFrame) {
        byte[] data = toBytes(((BinaryWebSocketFrame) msg).content());
        ((BinaryWebSocketFrame) msg).release();
        if (input != null) {
          input.add(data);
        } else if (clientChannel != null) {
          clientWriter.execute(() -> {
            try {
              clientChannel.join().write(data);
            } catch (IOException e) {
              ctx.close();
            }
          });
        }
      } else {
        ctx.fireChannelRead(msg);
      }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
      if (input != null) {
        input.end();
      }
      if (clientChannel != null) {
        clientChannel.thenAccept(SshChannel::close);
        clientWriter.shutdown();
      }
    }
  }

  /** Relay side of the host session. */
  private final class HostSessionHandler implements NoSecuritySshSession.Handler {
    @Override
    public CompletableFuture<byte[]> onGlobalRequest(String requestType, SshData.Reader data) {
      if ("tcpip-forward".equals(requestType) || "cancel-tcpip-forward".equals(requestType)) {
        data.readString(); // address
        int port = data.readInt();
        forwardTokens.add(data.available() > 0 ? data.readString() : null);
        ("tcpip-forward".equals(requestType) ? forwardedPorts : cancelledPorts).add(port);
        return CompletableFuture.completedFuture(
            new SshData.Writer().writeUint32(port).toByteArray());
      }
      return CompletableFuture.completedFuture(null);
    }

    @Override
    public CompletableFuture<ChannelOpenResult> onChannelOpening(
        SshChannel channel, SshData.Reader extraData) {
      return CompletableFuture.completedFuture(ChannelOpenResult.reject(1, "not supported"));
    }
  }

  /**
   * Opens a V2 "forwarded-tcpip" channel to the host, as the relay does for web clients.
   *
   * @param confirmation Receives the extra confirmation data.
   */
  CompletableFuture<SshChannel> openForwardedChannel(
      int port, CompletableFuture<SshData.Reader> confirmation) {
    byte[] request = new SshData.Writer()
        .writeString("127.0.0.1")
        .writeUint32(port)
        .writeString("203.0.113.7")
        .writeUint32(54321)
        .writeString("client-token")
        .writeBoolean(false)
        .toByteArray();
    return hostSession.thenCompose(session ->
        session.openChannel("forwarded-tcpip", request, confirmation));
  }
}

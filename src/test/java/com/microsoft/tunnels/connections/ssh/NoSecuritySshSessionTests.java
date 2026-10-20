// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections.ssh;

import com.microsoft.tunnels.connections.ssh.NoSecuritySshSession.ChannelOpenResult;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the "none" key-exchange SSH transport by connecting two sessions to each other.
 */
public class NoSecuritySshSessionTests {
  private NoSecuritySshSession client;
  private NoSecuritySshSession server;
  private TestHandler serverHandler;

  /** Thread-safe in-memory pipe. */
  static final class Pipe {
    private final BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
    private static final byte[] END = new byte[0];

    final OutputStream output = new OutputStream() {
      @Override
      public void write(int b) {
        write(new byte[] {(byte) b}, 0, 1);
      }

      @Override
      public void write(byte[] b, int off, int len) {
        byte[] copy = new byte[len];
        System.arraycopy(b, off, copy, 0, len);
        queue.add(copy);
      }

      @Override
      public void close() {
        queue.add(END);
      }
    };

    final InputStream input = new InputStream() {
      private byte[] current = new byte[0];
      private int position;

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
    };
  }

  static final class TestHandler implements NoSecuritySshSession.Handler {
    final BlockingQueue<SshChannel> openedChannels = new LinkedBlockingQueue<>();
    final CountDownLatch closed = new CountDownLatch(1);
    volatile int closeReason;

    @Override
    public CompletableFuture<ChannelOpenResult> onChannelOpening(
        SshChannel channel, SshData.Reader extraData) {
      if (!"test".equals(channel.getChannelType())) {
        return CompletableFuture.completedFuture(ChannelOpenResult.reject(
            SshMessages.OPEN_UNKNOWN_CHANNEL_TYPE, "nope"));
      }
      String hello = extraData.readString();
      byte[] confirmation = new SshData.Writer().writeString(hello + " back").toByteArray();
      return CompletableFuture.completedFuture(ChannelOpenResult.accept(
          confirmation, () -> openedChannels.add(channel)));
    }

    @Override
    public CompletableFuture<byte[]> onGlobalRequest(String requestType, SshData.Reader data) {
      switch (requestType) {
        case "echo":
          return CompletableFuture.completedFuture(
              new SshData.Writer().writeString(data.readString()).toByteArray());
        case "slow":
          return CompletableFuture.supplyAsync(() -> {
            try {
              Thread.sleep(200);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
            return new SshData.Writer().writeString("slow").toByteArray();
          });
        default:
          return CompletableFuture.completedFuture(null);
      }
    }

    @Override
    public void onClosed(int reason, String description) {
      closeReason = reason;
      closed.countDown();
    }
  }

  @Before
  public void connect() throws Exception {
    Pipe clientToServer = new Pipe();
    Pipe serverToClient = new Pipe();
    serverHandler = new TestHandler();
    client = new NoSecuritySshSession(
        serverToClient.input, clientToServer.output, "TestClient_1.0", true, null);
    server = new NoSecuritySshSession(
        clientToServer.input, serverToClient.output, "TestServer_1.0", false, serverHandler);
    CompletableFuture<Void> serverConnect = CompletableFuture.runAsync(() -> {
      try {
        server.connect();
      } catch (IOException e) {
        throw new RuntimeException(e);
      }
    });
    client.connect();
    serverConnect.get(5, TimeUnit.SECONDS);
    Assert.assertEquals("SSH-2.0-TestServer_1.0", client.getRemoteVersion());
    Assert.assertEquals("SSH-2.0-TestClient_1.0", server.getRemoteVersion());
  }

  @After
  public void close() {
    client.close();
    server.close();
  }

  @Test
  public void globalRequestsAreAnsweredInOrder() throws Exception {
    CompletableFuture<SshData.Reader> slow = client.request("slow", null);
    CompletableFuture<SshData.Reader> echo = client.request("echo",
        new SshData.Writer().writeString("hi").toByteArray());
    CompletableFuture<SshData.Reader> unknown = client.request("unknown", null);

    Assert.assertEquals("slow", slow.get(5, TimeUnit.SECONDS).readString());
    Assert.assertEquals("hi", echo.get(5, TimeUnit.SECONDS).readString());
    Assert.assertNull(unknown.get(5, TimeUnit.SECONDS));
  }

  @Test
  public void openChannelWithExtraDataAndTransferBeyondWindow() throws Exception {
    CompletableFuture<SshData.Reader> confirmation = new CompletableFuture<>();
    SshChannel clientChannel = client.openChannel(
        "test", new SshData.Writer().writeString("hello").toByteArray(), confirmation)
        .get(5, TimeUnit.SECONDS);
    Assert.assertEquals("hello back", confirmation.get().readString());
    SshChannel serverChannel = serverHandler.openedChannels.poll(5, TimeUnit.SECONDS);
    Assert.assertNotNull(serverChannel);

    // The server echoes everything back; EOF from the client causes the server to close.
    serverChannel.start(new SshChannel.Listener() {
      @Override
      public void onData(byte[] data) throws IOException {
        serverChannel.write(data);
      }

      @Override
      public void onEof() {
        serverChannel.sendEof();
        serverChannel.close();
      }
    });

    ByteArrayOutputStream received = new ByteArrayOutputStream();
    CountDownLatch clientClosed = new CountDownLatch(1);
    clientChannel.start(new SshChannel.Listener() {
      @Override
      public void onData(byte[] data) {
        received.write(data, 0, data.length);
      }

      @Override
      public void onClosed() {
        clientClosed.countDown();
      }
    });

    // Send several times the window size to exercise window adjustments in both directions.
    byte[] payload = new byte[SshChannel.DEFAULT_WINDOW_SIZE * 3 + 12345];
    new Random(42).nextBytes(payload);
    clientChannel.write(payload);
    clientChannel.sendEof();

    Assert.assertTrue("channel should close", clientClosed.await(20, TimeUnit.SECONDS));
    Assert.assertArrayEquals(payload, received.toByteArray());
  }

  @Test
  public void unknownChannelTypeIsRejected() throws Exception {
    try {
      client.openChannel("other", null, null).get(5, TimeUnit.SECONDS);
      Assert.fail("Expected the channel open to fail.");
    } catch (java.util.concurrent.ExecutionException e) {
      Assert.assertTrue(e.getCause().getMessage().contains("nope"));
    }
  }

  @Test
  public void disconnectReasonIsReported() throws Exception {
    client.close(SshMessages.DISCONNECT_TOO_MANY_CONNECTIONS, "too many");
    Assert.assertTrue(serverHandler.closed.await(5, TimeUnit.SECONDS));
    Assert.assertEquals(SshMessages.DISCONNECT_TOO_MANY_CONNECTIONS, serverHandler.closeReason);
    Assert.assertEquals(Integer.valueOf(SshMessages.DISCONNECT_TOO_MANY_CONNECTIONS),
        server.getClosedFuture().get(5, TimeUnit.SECONDS));
  }
}

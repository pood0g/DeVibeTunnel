// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.net.http.WebSocketHandshakeException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Adapts a binary websocket connection to a pair of byte streams.
 */
final class WebSocketStream implements WebSocket.Listener {
  private static final byte[] END = new byte[0];
  private static final Duration SEND_TIMEOUT = Duration.ofSeconds(60);

  private final BlockingQueue<byte[]> received = new LinkedBlockingQueue<>();
  private volatile WebSocket webSocket;
  private volatile boolean closed;

  private final InputStream inputStream = new InputStream() {
    private byte[] current;
    private int position;

    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      int count = read(one, 0, 1);
      return count < 0 ? -1 : one[0] & 0xff;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
      if (length == 0) {
        return 0;
      }
      while (current == null || position >= current.length) {
        if (current == END) {
          return -1;
        }
        try {
          current = received.take();
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new IOException("Interrupted while reading from websocket.", e);
        }
        position = 0;
        if (current == END) {
          received.add(END);
          return -1;
        }
      }
      int count = Math.min(length, current.length - position);
      System.arraycopy(current, position, buffer, offset, count);
      position += count;
      return count;
    }

    @Override
    public void close() {
      WebSocketStream.this.close();
    }
  };

  private final OutputStream outputStream = new OutputStream() {
    @Override
    public void write(int b) throws IOException {
      write(new byte[] {(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] buffer, int offset, int length) throws IOException {
      if (closed) {
        throw new IOException("Websocket is closed.");
      }
      byte[] copy = new byte[length];
      System.arraycopy(buffer, offset, copy, 0, length);
      try {
        webSocket.sendBinary(ByteBuffer.wrap(copy), true)
            .get(SEND_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while writing to websocket.", e);
      } catch (ExecutionException | TimeoutException e) {
        throw new IOException("Failed to write to websocket.", e);
      }
    }

    @Override
    public void close() {
      WebSocketStream.this.close();
    }
  };

  private WebSocketStream() {
  }

  /**
   * Connects a websocket.
   *
   * @param httpClient   HTTP client used for the connection.
   * @param uri          Websocket URI.
   * @param subprotocols Requested subprotocols in order of preference.
   * @param authHeader   Value of the Authorization header, or null.
   * @param timeout      Connection timeout.
   * @return A future that completes with the connected stream, or fails with
   *         {@link WebSocketHandshakeException} if the server rejected the upgrade.
   */
  static CompletableFuture<WebSocketStream> connect(
      HttpClient httpClient,
      URI uri,
      List<String> subprotocols,
      String authHeader,
      Duration timeout) {
    WebSocketStream stream = new WebSocketStream();
    WebSocket.Builder builder = httpClient.newWebSocketBuilder().connectTimeout(timeout);
    if (authHeader != null) {
      builder.header("Authorization", authHeader);
    }
    if (!subprotocols.isEmpty()) {
      builder.subprotocols(subprotocols.get(0),
          subprotocols.subList(1, subprotocols.size()).toArray(new String[0]));
    }
    return builder.buildAsync(uri, stream).thenApply(ws -> {
      stream.webSocket = ws;
      return stream;
    });
  }

  String getSubprotocol() {
    return webSocket.getSubprotocol();
  }

  InputStream getInputStream() {
    return inputStream;
  }

  OutputStream getOutputStream() {
    return outputStream;
  }

  void close() {
    if (closed) {
      return;
    }
    closed = true;
    received.add(END);
    WebSocket ws = webSocket;
    if (ws != null) {
      ws.sendClose(WebSocket.NORMAL_CLOSURE, "")
          .orTimeout(5, TimeUnit.SECONDS)
          .whenComplete((result, error) -> ws.abort());
    }
  }

  @Override
  public void onOpen(WebSocket ws) {
    ws.request(1);
  }

  @Override
  public CompletionStage<?> onBinary(WebSocket ws, ByteBuffer data, boolean last) {
    byte[] bytes = new byte[data.remaining()];
    data.get(bytes);
    if (bytes.length > 0) {
      received.add(bytes);
    }
    ws.request(1);
    return null;
  }

  @Override
  public CompletionStage<?> onText(WebSocket ws, CharSequence data, boolean last) {
    // The relay protocol is binary only.
    ws.request(1);
    return null;
  }

  @Override
  public CompletionStage<?> onClose(WebSocket ws, int statusCode, String reason) {
    closed = true;
    received.add(END);
    return null;
  }

  @Override
  public void onError(WebSocket ws, Throwable error) {
    closed = true;
    received.add(END);
  }
}

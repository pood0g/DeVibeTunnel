// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections.ssh;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An SSH connection-layer session that negotiates the non-standard "none" key exchange used
 * by the dev tunnels relay for host connections.
 *
 * <p>When both sides negotiate "none", the dev tunnels SSH library skips key exchange,
 * NEWKEYS, the service request and user authentication; the connection protocol (RFC 4254)
 * is available as soon as the KEXINIT messages are exchanged. Packets use the standard binary
 * packet framing with no encryption or MAC. This is safe because the websocket underneath is
 * TLS-protected and was authenticated by the relay with a tunnel access token.</p>
 */
public class NoSecuritySshSession implements Closeable {
  private static final Logger logger = LoggerFactory.getLogger(NoSecuritySshSession.class);
  private static final int MAX_PACKET_LENGTH = 256 * 1024 + 64;
  private static final String NONE = "none";
  private static final SecureRandom random = new SecureRandom();

  /**
   * Result of handling an incoming channel-open request.
   */
  public static final class ChannelOpenResult {
    final boolean accepted;
    final byte[] extraConfirmationData;
    final int failureReason;
    final String failureDescription;
    final Runnable onOpened;

    private ChannelOpenResult(
        boolean accepted,
        byte[] extraConfirmationData,
        Runnable onOpened,
        int failureReason,
        String description) {
      this.accepted = accepted;
      this.extraConfirmationData = extraConfirmationData;
      this.onOpened = onOpened;
      this.failureReason = failureReason;
      this.failureDescription = description;
    }

    /**
     * Accepts the channel.
     *
     * @param extraConfirmationData Extra data appended to the confirmation message, or null.
     * @param onOpened              Runs on a worker thread after the confirmation was sent, or
     *                              null. Data must not be sent on the channel before then.
     */
    public static ChannelOpenResult accept(byte[] extraConfirmationData, Runnable onOpened) {
      return new ChannelOpenResult(true, extraConfirmationData, onOpened, 0, null);
    }

    public static ChannelOpenResult reject(int reason, String description) {
      return new ChannelOpenResult(false, null, null, reason, description);
    }
  }

  /**
   * Handles session-level events. Callbacks run on the session's read thread and must not
   * block; return incomplete futures for work that takes time.
   */
  public interface Handler {
    /**
     * Handles a channel-open request from the remote side.
     *
     * @param channel   The new (not yet confirmed) channel.
     * @param extraData Reader positioned at the type-specific data of the open message.
     */
    default CompletableFuture<ChannelOpenResult> onChannelOpening(
        SshChannel channel, SshData.Reader extraData) {
      return CompletableFuture.completedFuture(ChannelOpenResult.reject(
          SshMessages.OPEN_UNKNOWN_CHANNEL_TYPE, "Unknown channel type"));
    }

    /**
     * Handles a global request from the remote side.
     *
     * @return A future resolving to response data on success, or null on failure.
     */
    default CompletableFuture<byte[]> onGlobalRequest(String requestType, SshData.Reader data) {
      return CompletableFuture.completedFuture(null);
    }

    /**
     * Called once when the session is closed.
     *
     * @param reason      SSH disconnect reason code.
     * @param description Disconnect description, if any.
     */
    default void onClosed(int reason, String description) {
    }
  }

  private final InputStream input;
  private final OutputStream output;
  private final String localVersion;
  private final boolean isClient;
  private final Handler handler;
  private final Object writeLock = new Object();
  private final Map<Integer, SshChannel> channels = new ConcurrentHashMap<>();
  private final Map<Integer, CompletableFuture<SshData.Reader>> pendingOpens =
      new ConcurrentHashMap<>();
  private final Deque<CompletableFuture<SshData.Reader>> pendingRequests = new ArrayDeque<>();
  private final Deque<CompletableFuture<byte[]>> pendingReplies = new ArrayDeque<>();
  private final AtomicInteger nextChannelId = new AtomicInteger();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final CompletableFuture<Integer> closedFuture = new CompletableFuture<>();
  private String remoteVersion;
  private long receiveSequence;
  private int lastDisconnectReason = SshMessages.DISCONNECT_CONNECTION_LOST;
  private String lastDisconnectDescription;

  /**
   * Creates a session over the given streams.
   *
   * @param input        Stream of bytes received from the remote side.
   * @param output       Stream for bytes sent to the remote side.
   * @param localVersion Software version part of the SSH identification string.
   * @param isClient     Whether this side is the SSH client.
   * @param handler      Handler for remote requests.
   */
  public NoSecuritySshSession(
      InputStream input,
      OutputStream output,
      String localVersion,
      boolean isClient,
      Handler handler) {
    this.input = input;
    this.output = output;
    this.localVersion = localVersion;
    this.isClient = isClient;
    this.handler = handler != null ? handler : new Handler() {
    };
  }

  public String getRemoteVersion() {
    return remoteVersion;
  }

  public boolean isClient() {
    return isClient;
  }

  public boolean isClosed() {
    return closed.get();
  }

  /**
   * A future that completes with the disconnect reason when the session closes.
   */
  public CompletableFuture<Integer> getClosedFuture() {
    return closedFuture;
  }

  /**
   * Exchanges identification strings and KEXINIT messages, then starts the read loop.
   *
   * @throws IOException if the remote side does not support the "none" key exchange.
   */
  public void connect() throws IOException {
    writeRaw(("SSH-2.0-" + localVersion + "\r\n").getBytes(StandardCharsets.US_ASCII));
    sendPacket(createKexInit());

    remoteVersion = readIdentification();
    logger.debug("Remote SSH version: {}", remoteVersion);

    byte[] payload = readPacket();
    while ((payload[0] & 0xff) != SshMessages.KEXINIT) {
      int type = payload[0] & 0xff;
      if (type == SshMessages.DISCONNECT) {
        handleDisconnect(new SshData.Reader(payload, 1, payload.length - 1));
        throw new IOException("Session was disconnected during key exchange.");
      }
      if (type != SshMessages.IGNORE && type != SshMessages.DEBUG) {
        throw new IOException("Expected KEXINIT but received message type " + type);
      }
      payload = readPacket();
    }

    SshData.Reader reader = new SshData.Reader(payload, 1, payload.length - 1);
    reader.skip(16); // cookie
    List<String> remoteKex = reader.readNameList();
    if (!remoteKex.contains(NONE)) {
      close(SshMessages.DISCONNECT_KEY_EXCHANGE_FAILED, "Key exchange 'none' is required.");
      throw new IOException("Remote side does not support the 'none' key exchange: " + remoteKex);
    }

    Thread readThread = new Thread(this::readLoop, "ssh-session-reader");
    readThread.setDaemon(true);
    readThread.start();
  }

  private byte[] createKexInit() {
    byte[] cookie = new byte[16];
    random.nextBytes(cookie);
    List<String> none = List.of(NONE);
    return new SshData.Writer()
        .writeByte(SshMessages.KEXINIT)
        .writeRaw(cookie)
        .writeNameList(none) // kex algorithms
        .writeNameList(none) // server host key algorithms
        .writeNameList(none) // encryption c2s
        .writeNameList(none) // encryption s2c
        .writeNameList(none) // mac c2s
        .writeNameList(none) // mac s2c
        .writeNameList(none) // compression c2s
        .writeNameList(none) // compression s2c
        .writeNameList(List.of()) // languages c2s
        .writeNameList(List.of()) // languages s2c
        .writeBoolean(false) // first kex packet follows
        .writeUint32(0) // reserved
        .toByteArray();
  }

  private String readIdentification() throws IOException {
    ByteArrayOutputStream line = new ByteArrayOutputStream();
    while (true) {
      int b = input.read();
      if (b < 0) {
        throw new EOFException("Connection closed before SSH identification was received.");
      }
      if (b == '\n') {
        String text = line.toString(StandardCharsets.UTF_8.name()).trim();
        if (text.startsWith("SSH-")) {
          return text;
        }
        line.reset();
      } else {
        line.write(b);
        if (line.size() > 8192) {
          throw new IOException("SSH identification line is too long.");
        }
      }
    }
  }

  private void readFully(byte[] buffer) throws IOException {
    int offset = 0;
    while (offset < buffer.length) {
      int count = input.read(buffer, offset, buffer.length - offset);
      if (count < 0) {
        throw new EOFException("Connection closed.");
      }
      offset += count;
    }
  }

  private byte[] readPacket() throws IOException {
    byte[] header = new byte[4];
    readFully(header);
    long packetLength = new SshData.Reader(header).readUint32();
    if (packetLength < 5 || packetLength > MAX_PACKET_LENGTH) {
      throw new IOException("Invalid SSH packet length: " + packetLength);
    }
    byte[] packet = new byte[(int) packetLength];
    readFully(packet);
    int paddingLength = packet[0] & 0xff;
    int payloadLength = (int) packetLength - paddingLength - 1;
    if (payloadLength < 1) {
      throw new IOException("Invalid SSH packet padding length.");
    }
    byte[] payload = new byte[payloadLength];
    System.arraycopy(packet, 1, payload, 0, payloadLength);
    receiveSequence++;
    return payload;
  }

  /**
   * Frames and sends one SSH packet.
   */
  void sendPacket(byte[] payload) throws IOException {
    if (closed.get()) {
      throw new IOException("Session is closed.");
    }
    int blockSize = 8;
    int paddingLength = blockSize - ((4 + 1 + payload.length) % blockSize);
    if (paddingLength < 4) {
      paddingLength += blockSize;
    }
    byte[] padding = new byte[paddingLength];
    random.nextBytes(padding);
    byte[] packet = new SshData.Writer()
        .writeUint32(1 + payload.length + paddingLength)
        .writeByte(paddingLength)
        .writeRaw(payload)
        .writeRaw(padding)
        .toByteArray();
    writeRaw(packet);
  }

  private void writeRaw(byte[] bytes) throws IOException {
    synchronized (writeLock) {
      output.write(bytes);
      output.flush();
    }
  }

  private void readLoop() {
    int reason = SshMessages.DISCONNECT_CONNECTION_LOST;
    String description = "Connection lost.";
    try {
      while (!closed.get()) {
        byte[] payload = readPacket();
        if (!handleMessage(payload)) {
          reason = lastDisconnectReason;
          description = lastDisconnectDescription;
          break;
        }
      }
    } catch (IOException | RuntimeException e) {
      if (!closed.get()) {
        logger.debug("SSH session read loop ended: {}", e.toString());
        description = e.getMessage();
      }
    }
    onClosed(reason, description);
  }

  private boolean handleMessage(byte[] payload) throws IOException {
    int type = payload[0] & 0xff;
    SshData.Reader reader = new SshData.Reader(payload, 1, payload.length - 1);
    switch (type) {
      case SshMessages.DISCONNECT:
        handleDisconnect(reader);
        return false;
      case SshMessages.IGNORE:
      case SshMessages.DEBUG:
      case SshMessages.EXT_INFO:
      case SshMessages.UNIMPLEMENTED:
        return true;
      case SshMessages.GLOBAL_REQUEST:
        handleGlobalRequest(reader);
        return true;
      case SshMessages.REQUEST_SUCCESS:
      case SshMessages.REQUEST_FAILURE: {
        CompletableFuture<SshData.Reader> pending;
        synchronized (pendingRequests) {
          pending = pendingRequests.pollFirst();
        }
        if (pending != null) {
          pending.complete(type == SshMessages.REQUEST_SUCCESS ? reader : null);
        }
        return true;
      }
      case SshMessages.CHANNEL_OPEN:
        handleChannelOpen(reader);
        return true;
      case SshMessages.CHANNEL_OPEN_CONFIRMATION:
        handleChannelOpenConfirmation(reader);
        return true;
      case SshMessages.CHANNEL_OPEN_FAILURE: {
        int localId = reader.readInt();
        int failureReason = reader.readInt();
        String failureDescription = reader.readString();
        SshChannel channel = channels.remove(localId);
        if (channel != null) {
          channel.markClosed();
        }
        CompletableFuture<SshData.Reader> pending = pendingOpens.remove(localId);
        if (pending != null) {
          pending.completeExceptionally(new IOException(
              "Channel open failed (" + failureReason + "): " + failureDescription));
        }
        return true;
      }
      case SshMessages.CHANNEL_WINDOW_ADJUST: {
        SshChannel channel = channels.get(reader.readInt());
        if (channel != null) {
          channel.onWindowAdjust(reader.readUint32());
        }
        return true;
      }
      case SshMessages.CHANNEL_DATA: {
        SshChannel channel = channels.get(reader.readInt());
        byte[] data = reader.readBinary();
        if (channel != null) {
          channel.onDataReceived(data);
        }
        return true;
      }
      case SshMessages.CHANNEL_EXTENDED_DATA: {
        SshChannel channel = channels.get(reader.readInt());
        reader.readUint32(); // data type code
        byte[] data = reader.readBinary();
        if (channel != null) {
          // Extended data is not expected on port-forwarding channels; acknowledge and drop it.
          sendPacket(new SshData.Writer()
              .writeByte(SshMessages.CHANNEL_WINDOW_ADJUST)
              .writeUint32(channel.getRemoteId())
              .writeUint32(data.length)
              .toByteArray());
        }
        return true;
      }
      case SshMessages.CHANNEL_EOF: {
        SshChannel channel = channels.get(reader.readInt());
        if (channel != null) {
          channel.onEofReceived();
        }
        return true;
      }
      case SshMessages.CHANNEL_CLOSE: {
        SshChannel channel = channels.get(reader.readInt());
        if (channel != null) {
          channel.onCloseReceived();
        }
        return true;
      }
      case SshMessages.CHANNEL_REQUEST: {
        SshChannel channel = channels.get(reader.readInt());
        reader.readString(); // request type
        boolean wantReply = reader.readBoolean();
        if (channel != null && wantReply) {
          sendPacket(new SshData.Writer()
              .writeByte(SshMessages.CHANNEL_FAILURE)
              .writeUint32(channel.getRemoteId())
              .toByteArray());
        }
        return true;
      }
      case SshMessages.CHANNEL_SUCCESS:
      case SshMessages.CHANNEL_FAILURE:
        return true;
      default:
        logger.debug("Unimplemented SSH message type {}", type);
        sendPacket(new SshData.Writer()
            .writeByte(SshMessages.UNIMPLEMENTED)
            .writeUint32(receiveSequence - 1)
            .toByteArray());
        return true;
    }
  }

  private void handleDisconnect(SshData.Reader reader) {
    lastDisconnectReason = reader.readInt();
    lastDisconnectDescription = reader.available() >= 4 ? reader.readString() : "";
    logger.debug("Received SSH disconnect ({}): {}",
        lastDisconnectReason, lastDisconnectDescription);
  }

  private void handleGlobalRequest(SshData.Reader reader) throws IOException {
    String requestType = reader.readString();
    boolean wantReply = reader.readBoolean();
    CompletableFuture<byte[]> response;
    try {
      response = handler.onGlobalRequest(requestType, reader);
    } catch (RuntimeException e) {
      logger.warn("Error handling global request {}: {}", requestType, e.toString());
      response = CompletableFuture.completedFuture(null);
    }
    if (!wantReply) {
      return;
    }
    // Replies to global requests must be sent in the order the requests were received.
    synchronized (pendingReplies) {
      pendingReplies.addLast(response);
    }
    response.whenComplete((result, error) -> flushReplies());
  }

  private void flushReplies() {
    synchronized (pendingReplies) {
      while (!pendingReplies.isEmpty() && pendingReplies.peekFirst().isDone()) {
        CompletableFuture<byte[]> next = pendingReplies.pollFirst();
        byte[] result = next.isCompletedExceptionally() ? null : next.join();
        SshData.Writer writer = new SshData.Writer().writeByte(
            result != null ? SshMessages.REQUEST_SUCCESS : SshMessages.REQUEST_FAILURE);
        if (result != null) {
          writer.writeRaw(result);
        }
        try {
          sendPacket(writer.toByteArray());
        } catch (IOException e) {
          logger.debug("Failed to send global request reply.", e);
        }
      }
    }
  }

  private void handleChannelOpen(SshData.Reader reader) throws IOException {
    String channelType = reader.readString();
    int remoteId = reader.readInt();
    long remoteWindow = reader.readUint32();
    int remoteMaxPacket = reader.readInt();
    int localId = nextChannelId.getAndIncrement();
    SshChannel channel = new SshChannel(this, channelType, localId);
    channel.setRemote(remoteId, remoteWindow, remoteMaxPacket);

    CompletableFuture<ChannelOpenResult> result;
    try {
      result = handler.onChannelOpening(channel, reader);
    } catch (RuntimeException e) {
      logger.warn("Error handling channel open: {}", e.toString());
      result = CompletableFuture.completedFuture(
          ChannelOpenResult.reject(SshMessages.OPEN_CONNECT_FAILED, e.getMessage()));
    }
    // Register before confirming so data that follows the confirmation is not lost.
    channels.put(localId, channel);
    result.whenComplete((openResult, error) -> {
      try {
        if (error == null && openResult != null && openResult.accepted) {
          SshData.Writer writer = new SshData.Writer()
              .writeByte(SshMessages.CHANNEL_OPEN_CONFIRMATION)
              .writeUint32(remoteId)
              .writeUint32(localId)
              .writeUint32(channel.getLocalWindowSize())
              .writeUint32(SshChannel.DEFAULT_MAX_PACKET_SIZE);
          if (openResult.extraConfirmationData != null) {
            writer.writeRaw(openResult.extraConfirmationData);
          }
          sendPacket(writer.toByteArray());
          if (openResult.onOpened != null) {
            CompletableFuture.runAsync(openResult.onOpened).exceptionally(e -> {
              logger.warn("Error starting channel {}: {}", localId, e.toString());
              channel.close();
              return null;
            });
          }
        } else {
          channels.remove(localId);
          channel.markClosed();
          int reason = openResult != null
              ? openResult.failureReason : SshMessages.OPEN_CONNECT_FAILED;
          String description = openResult != null ? openResult.failureDescription
              : (error != null ? error.getMessage() : "Channel open failed");
          sendPacket(new SshData.Writer()
              .writeByte(SshMessages.CHANNEL_OPEN_FAILURE)
              .writeUint32(remoteId)
              .writeUint32(reason)
              .writeString(description)
              .writeString("")
              .toByteArray());
        }
      } catch (IOException e) {
        logger.debug("Failed to reply to channel open.", e);
      }
    });
  }

  private void handleChannelOpenConfirmation(SshData.Reader reader) {
    int localId = reader.readInt();
    int remoteId = reader.readInt();
    long remoteWindow = reader.readUint32();
    int remoteMaxPacket = reader.readInt();
    SshChannel channel = channels.get(localId);
    if (channel != null) {
      channel.setRemote(remoteId, remoteWindow, remoteMaxPacket);
    }
    CompletableFuture<SshData.Reader> pending = pendingOpens.remove(localId);
    if (pending != null) {
      pending.complete(reader);
    }
  }

  /**
   * Sends a global request and waits for the reply.
   *
   * @return A future resolving to a reader over the response data, or null on failure.
   */
  public CompletableFuture<SshData.Reader> request(String requestType, byte[] requestData) {
    CompletableFuture<SshData.Reader> result = new CompletableFuture<>();
    SshData.Writer writer = new SshData.Writer()
        .writeByte(SshMessages.GLOBAL_REQUEST)
        .writeString(requestType)
        .writeBoolean(true);
    if (requestData != null) {
      writer.writeRaw(requestData);
    }
    synchronized (pendingRequests) {
      pendingRequests.addLast(result);
      try {
        sendPacket(writer.toByteArray());
      } catch (IOException e) {
        pendingRequests.remove(result);
        result.completeExceptionally(e);
      }
    }
    return result;
  }

  /**
   * Opens a channel to the remote side.
   *
   * @param channelType     Channel type name.
   * @param extraData       Type-specific data appended to the open message, or null.
   * @param confirmationOut Receives a reader over extra confirmation data, if not null.
   */
  public CompletableFuture<SshChannel> openChannel(
      String channelType,
      byte[] extraData,
      CompletableFuture<SshData.Reader> confirmationOut) {
    int localId = nextChannelId.getAndIncrement();
    SshChannel channel = new SshChannel(this, channelType, localId);
    CompletableFuture<SshData.Reader> pending = new CompletableFuture<>();
    channels.put(localId, channel);
    pendingOpens.put(localId, pending);
    SshData.Writer writer = new SshData.Writer()
        .writeByte(SshMessages.CHANNEL_OPEN)
        .writeString(channelType)
        .writeUint32(localId)
        .writeUint32(channel.getLocalWindowSize())
        .writeUint32(SshChannel.DEFAULT_MAX_PACKET_SIZE);
    if (extraData != null) {
      writer.writeRaw(extraData);
    }
    try {
      sendPacket(writer.toByteArray());
    } catch (IOException e) {
      channels.remove(localId);
      pendingOpens.remove(localId);
      return CompletableFuture.failedFuture(e);
    }
    return pending.thenApply(confirmation -> {
      if (confirmationOut != null) {
        confirmationOut.complete(confirmation);
      }
      return channel;
    });
  }

  void removeChannel(SshChannel channel) {
    channels.remove(channel.getLocalId(), channel);
  }

  /**
   * Sends a disconnect message and closes the session.
   */
  public void close(int reason, String description) {
    if (!closed.get()) {
      try {
        sendPacket(new SshData.Writer()
            .writeByte(SshMessages.DISCONNECT)
            .writeUint32(reason)
            .writeString(description)
            .writeString("")
            .toByteArray());
      } catch (IOException e) {
        logger.debug("Failed to send disconnect.", e);
      }
    }
    onClosed(reason, description);
  }

  @Override
  public void close() {
    close(SshMessages.DISCONNECT_BY_APPLICATION, "Closed by application.");
  }

  private void onClosed(int reason, String description) {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    for (SshChannel channel : channels.values()) {
      channel.markClosed();
    }
    channels.clear();
    for (CompletableFuture<SshData.Reader> pending : pendingOpens.values()) {
      pending.completeExceptionally(new IOException("Session closed."));
    }
    pendingOpens.clear();
    synchronized (pendingRequests) {
      for (CompletableFuture<SshData.Reader> pending : pendingRequests) {
        pending.completeExceptionally(new IOException("Session closed."));
      }
      pendingRequests.clear();
    }
    try {
      output.close();
    } catch (IOException e) {
      // Ignore.
    }
    try {
      input.close();
    } catch (IOException e) {
      // Ignore.
    }
    try {
      handler.onClosed(reason, description);
    } finally {
      closedFuture.complete(reason);
    }
  }
}

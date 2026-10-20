// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections.ssh;

import java.io.IOException;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A channel multiplexed over a {@link NoSecuritySshSession}.
 *
 * <p>Incoming data is queued and delivered to a {@link Listener} on a dedicated thread, so a
 * slow consumer never blocks the session's read loop. The local receive window is only
 * re-opened after the listener has consumed the data, which gives end-to-end back-pressure.
 * Writes block while the remote window is exhausted.</p>
 */
public class SshChannel {
  /** Initial receive window advertised for channels. */
  public static final int DEFAULT_WINDOW_SIZE = 1024 * 1024;
  /** Maximum packet size advertised for channels. */
  public static final int DEFAULT_MAX_PACKET_SIZE = 32 * 1024;

  private static final Logger logger = LoggerFactory.getLogger(SshChannel.class);
  private static final Object EOF = new Object();
  private static final Object CLOSED = new Object();

  /**
   * Receives events for a channel. Callbacks are invoked on the channel's own thread.
   */
  public interface Listener {
    void onData(byte[] data) throws IOException;

    default void onEof() {
    }

    default void onClosed() {
    }
  }

  private final NoSecuritySshSession session;
  private final String channelType;
  private final int localId;
  private final int localWindowSize;
  private int remoteId;
  private long remoteWindow;
  private int remoteMaxPacket;
  private final Object windowLock = new Object();
  private final BlockingQueue<Object> inbound = new LinkedBlockingQueue<>();
  private final AtomicBoolean started = new AtomicBoolean();
  private final AtomicBoolean eofSent = new AtomicBoolean();
  private final AtomicBoolean closeSent = new AtomicBoolean();
  private volatile boolean closed;
  private long unacknowledgedBytes;

  SshChannel(NoSecuritySshSession session, String channelType, int localId) {
    this.session = session;
    this.channelType = channelType;
    this.localId = localId;
    this.localWindowSize = DEFAULT_WINDOW_SIZE;
  }

  void setRemote(int remoteId, long remoteWindow, int remoteMaxPacket) {
    synchronized (windowLock) {
      this.remoteId = remoteId;
      this.remoteWindow = remoteWindow;
      this.remoteMaxPacket = Math.max(1, remoteMaxPacket);
    }
  }

  public String getChannelType() {
    return channelType;
  }

  public int getLocalId() {
    return localId;
  }

  int getRemoteId() {
    return remoteId;
  }

  int getLocalWindowSize() {
    return localWindowSize;
  }

  public NoSecuritySshSession getSession() {
    return session;
  }

  public boolean isClosed() {
    return closed;
  }

  /**
   * Starts delivering queued and future events to the listener. May be called only once.
   */
  public void start(Listener listener) {
    if (!started.compareAndSet(false, true)) {
      throw new IllegalStateException("Channel listener was already started.");
    }
    Thread thread = new Thread(() -> dispatch(listener),
        "ssh-channel-" + channelType + "-" + localId);
    thread.setDaemon(true);
    thread.start();
  }

  private void dispatch(Listener listener) {
    try {
      while (true) {
        Object item = inbound.take();
        if (item == CLOSED) {
          listener.onClosed();
          return;
        } else if (item == EOF) {
          listener.onEof();
        } else {
          byte[] data = (byte[]) item;
          try {
            listener.onData(data);
          } catch (IOException e) {
            logger.debug("Channel {} listener failed; closing channel.", localId, e);
            close();
          }
          consumed(data.length);
        }
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException e) {
      logger.warn("Error handling data for channel {}: {}", localId, e.toString());
      close();
      listener.onClosed();
    }
  }

  private void consumed(int count) {
    long adjust = 0;
    synchronized (this) {
      unacknowledgedBytes += count;
      if (unacknowledgedBytes >= localWindowSize / 4) {
        adjust = unacknowledgedBytes;
        unacknowledgedBytes = 0;
      }
    }
    if (adjust > 0 && !closed) {
      try {
        session.sendPacket(new SshData.Writer()
            .writeByte(SshMessages.CHANNEL_WINDOW_ADJUST)
            .writeUint32(remoteId)
            .writeUint32(adjust)
            .toByteArray());
      } catch (IOException e) {
        logger.debug("Failed to send window adjust for channel {}.", localId, e);
      }
    }
  }

  void onDataReceived(byte[] data) {
    if (!closed) {
      inbound.add(data);
    }
  }

  void onEofReceived() {
    inbound.add(EOF);
  }

  void onWindowAdjust(long bytes) {
    synchronized (windowLock) {
      remoteWindow = Math.min(remoteWindow + bytes, 0xffffffffL);
      windowLock.notifyAll();
    }
  }

  void onCloseReceived() {
    markClosed();
    if (closeSent.compareAndSet(false, true)) {
      sendClose();
    }
    session.removeChannel(this);
  }

  /** Marks the channel closed without sending anything, e.g. when the session drops. */
  void markClosed() {
    if (closed) {
      return;
    }
    closed = true;
    synchronized (windowLock) {
      windowLock.notifyAll();
    }
    inbound.add(CLOSED);
  }

  /**
   * Sends data, blocking while the remote window is exhausted.
   */
  public void write(byte[] data, int offset, int length) throws IOException {
    int position = offset;
    int end = offset + length;
    while (position < end) {
      int chunk;
      synchronized (windowLock) {
        while (remoteWindow <= 0 && !closed) {
          try {
            windowLock.wait();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for channel window.", e);
          }
        }
        if (closed || eofSent.get()) {
          throw new IOException("Channel is closed.");
        }
        chunk = (int) Math.min(Math.min(end - position, remoteMaxPacket), remoteWindow);
        remoteWindow -= chunk;
      }
      session.sendPacket(new SshData.Writer()
          .writeByte(SshMessages.CHANNEL_DATA)
          .writeUint32(remoteId)
          .writeUint32(chunk)
          .writeRaw(data, position, chunk)
          .toByteArray());
      position += chunk;
    }
  }

  public void write(byte[] data) throws IOException {
    write(data, 0, data.length);
  }

  /**
   * Signals that no more data will be sent on this channel.
   */
  public void sendEof() {
    if (closed || !eofSent.compareAndSet(false, true)) {
      return;
    }
    try {
      session.sendPacket(new SshData.Writer()
          .writeByte(SshMessages.CHANNEL_EOF)
          .writeUint32(remoteId)
          .toByteArray());
    } catch (IOException e) {
      logger.debug("Failed to send EOF for channel {}.", localId, e);
    }
  }

  /**
   * Closes the channel. The channel is fully released when the remote side confirms.
   */
  public void close() {
    if (closeSent.compareAndSet(false, true)) {
      sendClose();
    }
    markClosed();
  }

  private void sendClose() {
    try {
      session.sendPacket(new SshData.Writer()
          .writeByte(SshMessages.CHANNEL_CLOSE)
          .writeUint32(remoteId)
          .toByteArray());
    } catch (IOException e) {
      logger.debug("Failed to send close for channel {}.", localId, e);
    }
  }
}

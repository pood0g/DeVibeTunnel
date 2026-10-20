// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.connections.ssh.SshChannel;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.apache.sshd.common.future.CloseFuture;
import org.apache.sshd.common.future.DefaultCloseFuture;
import org.apache.sshd.common.future.SshFutureListener;
import org.apache.sshd.common.io.IoHandler;
import org.apache.sshd.common.io.IoService;
import org.apache.sshd.common.io.IoSession;
import org.apache.sshd.common.io.IoWriteFuture;
import org.apache.sshd.common.util.buffer.Buffer;
import org.apache.sshd.common.util.buffer.ByteArrayBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A MINA {@link IoSession} whose transport is an SSH channel of the relay session.
 *
 * <p>This lets a standard MINA SSH server session run inside a "client-ssh-session-stream"
 * channel (V1 relay protocol): bytes received on the channel are fed to the session handler,
 * and bytes written by the session are sent on the channel.</p>
 */
final class ChannelIoSession implements IoSession {
  private static final Logger logger = LoggerFactory.getLogger(ChannelIoSession.class);
  private static final AtomicLong nextId = new AtomicLong(1);
  private static final SocketAddress LOOPBACK =
      new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);

  private final long id = nextId.getAndIncrement();
  private final SshChannel channel;
  private final IoHandler handler;
  private final Map<Object, Object> attributes = new ConcurrentHashMap<>();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final DefaultCloseFuture closeFuture = new DefaultCloseFuture(this, this);

  ChannelIoSession(SshChannel channel, IoHandler handler) {
    this.channel = channel;
    this.handler = handler;
  }

  /**
   * Creates the SSH session for this transport and starts delivering channel data to it.
   */
  void start() throws Exception {
    handler.sessionCreated(this);
    channel.start(new SshChannel.Listener() {
      @Override
      public void onData(byte[] data) throws IOException {
        try {
          handler.messageReceived(ChannelIoSession.this, new ByteArrayBuffer(data));
        } catch (IOException e) {
          throw e;
        } catch (Exception e) {
          throw new IOException(e);
        }
      }

      @Override
      public void onEof() {
        close(true);
      }

      @Override
      public void onClosed() {
        close(true);
      }
    });
  }

  @Override
  public long getId() {
    return id;
  }

  @Override
  public SocketAddress getAcceptanceAddress() {
    return LOOPBACK;
  }

  @Override
  public SocketAddress getLocalAddress() {
    return LOOPBACK;
  }

  @Override
  public SocketAddress getRemoteAddress() {
    return LOOPBACK;
  }

  @Override
  public Object getAttribute(Object key) {
    return attributes.get(key);
  }

  @Override
  public Object setAttribute(Object key, Object value) {
    return attributes.put(key, value);
  }

  @Override
  public Object setAttributeIfAbsent(Object key, Object value) {
    return attributes.putIfAbsent(key, value);
  }

  @Override
  public Object removeAttribute(Object key) {
    return attributes.remove(key);
  }

  @Override
  public IoWriteFuture writeBuffer(Buffer buffer) throws IOException {
    WriteFuture future = new WriteFuture(this);
    try {
      channel.write(buffer.array(), buffer.rpos(), buffer.available());
      future.setValue(Boolean.TRUE);
    } catch (IOException e) {
      future.setValue(e);
    }
    return future;
  }

  @Override
  public CloseFuture close(boolean immediately) {
    if (closed.compareAndSet(false, true)) {
      channel.close();
      try {
        handler.sessionClosed(this);
      } catch (Exception e) {
        logger.debug("Error closing client SSH session.", e);
      }
      closeFuture.setClosed();
    }
    return closeFuture;
  }

  @Override
  public IoService getService() {
    // Not backed by a MINA IoService; the session-count limits that need it are not used.
    return null;
  }

  @Override
  public void shutdownOutputStream() {
    channel.sendEof();
  }

  @Override
  public boolean isClosed() {
    return closed.get();
  }

  @Override
  public boolean isClosing() {
    return closed.get();
  }

  @Override
  public void addCloseFutureListener(SshFutureListener<CloseFuture> listener) {
    closeFuture.addListener(listener);
  }

  @Override
  public void removeCloseFutureListener(SshFutureListener<CloseFuture> listener) {
    closeFuture.removeListener(listener);
  }

  private static final class WriteFuture
      extends org.apache.sshd.common.io.AbstractIoWriteFuture {
    WriteFuture(Object id) {
      super(id, null);
    }
  }
}

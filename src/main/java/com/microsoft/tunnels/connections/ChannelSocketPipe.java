// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.connections.ssh.SshChannel;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pumps data in both directions between an SSH channel and a TCP socket, propagating
 * half-close (EOF) and close in each direction.
 */
final class ChannelSocketPipe implements SshChannel.Listener {
  private static final Logger logger = LoggerFactory.getLogger(ChannelSocketPipe.class);
  private static final int BUFFER_SIZE = 32 * 1024;

  private final SshChannel channel;
  private final Socket socket;
  private final OutputStream socketOutput;
  private boolean localEof;
  private boolean remoteEof;

  private ChannelSocketPipe(SshChannel channel, Socket socket) throws IOException {
    this.channel = channel;
    this.socket = socket;
    this.socketOutput = socket.getOutputStream();
  }

  /**
   * Starts pumping between the channel and socket. The channel must already be confirmed.
   */
  static void start(SshChannel channel, Socket socket) throws IOException {
    ChannelSocketPipe pipe = new ChannelSocketPipe(channel, socket);
    channel.start(pipe);
    Thread reader = new Thread(pipe::pumpSocketToChannel,
        "tunnel-forward-" + socket.getPort() + "-" + channel.getLocalId());
    reader.setDaemon(true);
    reader.start();
  }

  private void pumpSocketToChannel() {
    byte[] buffer = new byte[BUFFER_SIZE];
    try {
      InputStream input = socket.getInputStream();
      int count;
      while ((count = input.read(buffer)) >= 0) {
        channel.write(buffer, 0, count);
      }
      channel.sendEof();
      boolean closeNow;
      synchronized (this) {
        localEof = true;
        closeNow = remoteEof;
      }
      if (closeNow) {
        closeAll();
      }
    } catch (IOException e) {
      if (!channel.isClosed()) {
        logger.debug("Forwarded connection ended: {}", e.toString());
      }
      closeAll();
    }
  }

  @Override
  public void onData(byte[] data) throws IOException {
    socketOutput.write(data);
    socketOutput.flush();
  }

  @Override
  public void onEof() {
    boolean closeNow;
    synchronized (this) {
      remoteEof = true;
      closeNow = localEof;
    }
    try {
      socket.shutdownOutput();
    } catch (IOException e) {
      // Ignore; the socket may already be closed.
    }
    if (closeNow) {
      closeAll();
    }
  }

  @Override
  public void onClosed() {
    closeSocket();
  }

  private void closeAll() {
    channel.close();
    closeSocket();
  }

  private void closeSocket() {
    try {
      socket.close();
    } catch (IOException e) {
      // Ignore.
    }
  }
}

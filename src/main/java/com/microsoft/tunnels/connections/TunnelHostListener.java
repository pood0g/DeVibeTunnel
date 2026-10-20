// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import java.util.EventListener;

/**
 * Receives connection events from a {@link TunnelHost}. All methods have empty defaults.
 */
public interface TunnelHostListener extends EventListener {
  /**
   * The host connected (or reconnected) to the relay.
   *
   * @param protocol Negotiated websocket subprotocol.
   */
  default void onConnected(String protocol) {
  }

  /**
   * The host lost its relay connection.
   *
   * @param reason       Description of the disconnect.
   * @param reconnecting Whether the host will try to reconnect.
   */
  default void onDisconnected(String reason, boolean reconnecting) {
  }

  /**
   * A client opened a connection that is being forwarded to a local port.
   *
   * @param port       Local port number.
   * @param originator Description of the remote originator, if known.
   */
  default void onForwardedConnection(int port, String originator) {
  }

  /**
   * A client SSH session (V1 protocol) connected or disconnected.
   *
   * @param connected True when connected, false when disconnected.
   */
  default void onClientSessionChanged(boolean connected) {
  }
}

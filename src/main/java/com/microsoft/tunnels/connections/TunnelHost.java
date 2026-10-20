// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.contracts.Tunnel;

import java.util.concurrent.CompletableFuture;

/**
 * Interface for a host capable of accepting connections to a tunnel and forwarding them to
 * local ports.
 */
public interface TunnelHost extends AutoCloseable {
  /**
   * Connects to a tunnel as a host and starts accepting incoming connections to the local
   * ports defined on the tunnel.
   *
   * @param tunnel Tunnel to host. If it does not include a host access token, one is
   *               requested from the management service.
   * @return A future that completes when the host is connected to the relay.
   */
  CompletableFuture<Void> connectAsync(Tunnel tunnel);

  /**
   * Re-reads the tunnel ports from the management service and starts (or stops) forwarding
   * ports that were added (or removed).
   */
  CompletableFuture<Void> refreshPortsAsync();

  /**
   * Disconnects from the relay and deletes the host endpoint.
   */
  void stop();

  @Override
  default void close() {
    stop();
  }
}

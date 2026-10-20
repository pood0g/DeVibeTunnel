// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections;

import com.microsoft.tunnels.contracts.ClusterDetails;
import com.microsoft.tunnels.contracts.ClusterRecommendationResponse;
import com.microsoft.tunnels.contracts.NamedRateStatus;
import com.microsoft.tunnels.contracts.Tunnel;
import com.microsoft.tunnels.contracts.TunnelEndpoint;
import com.microsoft.tunnels.contracts.TunnelPort;
import com.microsoft.tunnels.contracts.TunnelRelayTunnelEndpoint;
import com.microsoft.tunnels.management.ITunnelManagementClient;
import com.microsoft.tunnels.management.TunnelRequestOptions;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory management client for host tests: one tunnel whose ports can be changed, and
 * endpoint registration that points at a {@link FakeRelay}.
 */
final class FakeManagementClient implements ITunnelManagementClient {
  static final String HOST_TOKEN = "host-token";

  final List<TunnelPort> ports = new CopyOnWriteArrayList<>();
  final List<TunnelEndpoint> registeredEndpoints = new CopyOnWriteArrayList<>();
  final List<String> deletedEndpoints = new CopyOnWriteArrayList<>();
  private final String hostRelayUri;

  FakeManagementClient(String hostRelayUri, int... portNumbers) {
    this.hostRelayUri = hostRelayUri;
    for (int portNumber : portNumbers) {
      addPort(portNumber);
    }
  }

  void addPort(int portNumber) {
    TunnelPort port = new TunnelPort();
    port.portNumber = portNumber;
    port.protocol = "http";
    ports.add(port);
  }

  void removePort(int portNumber) {
    ports.removeIf(p -> p.portNumber == portNumber);
  }

  static Tunnel tunnelReference() {
    Tunnel tunnel = new Tunnel();
    tunnel.tunnelId = "test-tunnel";
    tunnel.clusterId = "test1";
    return tunnel;
  }

  @Override
  public CompletableFuture<Tunnel> getTunnelAsync(Tunnel tunnel, TunnelRequestOptions options) {
    Tunnel result = tunnelReference();
    result.accessTokens = Map.of("host", HOST_TOKEN, "connect", "connect-token");
    result.ports = ports.toArray(new TunnelPort[0]);
    return CompletableFuture.completedFuture(result);
  }

  @Override
  public CompletableFuture<TunnelEndpoint> updateTunnelEndpointAsync(
      Tunnel tunnel, TunnelEndpoint endpoint, TunnelRequestOptions options) {
    registeredEndpoints.add(endpoint);
    TunnelRelayTunnelEndpoint result = new TunnelRelayTunnelEndpoint();
    result.id = endpoint.id;
    result.hostId = endpoint.hostId;
    result.connectionMode = endpoint.connectionMode;
    result.hostPublicKeys = endpoint.hostPublicKeys;
    result.hostRelayUri = hostRelayUri;
    return CompletableFuture.completedFuture(result);
  }

  @Override
  public CompletableFuture<Boolean> deleteTunnelEndpointsAsync(
      Tunnel tunnel, String id, TunnelRequestOptions options) {
    deletedEndpoints.add(id);
    return CompletableFuture.completedFuture(true);
  }

  @Override
  public CompletableFuture<Collection<TunnelPort>> listTunnelPortsAsync(
      Tunnel tunnel, TunnelRequestOptions options) {
    return CompletableFuture.completedFuture(new ArrayList<>(ports));
  }

  @Override
  public CompletableFuture<Collection<Tunnel>> listTunnelsAsync(
      String clusterId, String domain, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Tunnel> createTunnelAsync(Tunnel tunnel, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Tunnel> updateTunnelAsync(Tunnel tunnel, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Tunnel> createOrUpdateTunnelAsync(
      Tunnel tunnel, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Boolean> deleteTunnelAsync(Tunnel tunnel, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<TunnelPort> getTunnelPortAsync(
      Tunnel tunnel, int portNumber, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<TunnelPort> createTunnelPortAsync(
      Tunnel tunnel, TunnelPort tunnelPort, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<TunnelPort> updateTunnelPortAsync(
      Tunnel tunnel, TunnelPort tunnelPort, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<TunnelPort> createOrUpdateTunnelPortAsync(
      Tunnel tunnel, TunnelPort tunnelPort, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Boolean> deleteTunnelPortAsync(
      Tunnel tunnel, int portNumber, TunnelRequestOptions options) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Boolean> checkNameAvailabilityAsync(String name) {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Collection<ClusterDetails>> listClustersAsync() {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<Collection<NamedRateStatus>> listUserLimitsAsync() {
    throw new UnsupportedOperationException();
  }

  @Override
  public CompletableFuture<ClusterRecommendationResponse> getClusterRecommendationsAsync(
      String preferredClusterId, String requiredGeo) {
    throw new UnsupportedOperationException();
  }
}

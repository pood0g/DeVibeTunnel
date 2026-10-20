// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.auth;

import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator.DeviceCode;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator.GitHubAuthenticationException;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator.GitHubToken;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the GitHub device flow against a local mock of the GitHub OAuth endpoints.
 */
public class GitHubDeviceCodeAuthenticatorTests {
  private HttpServer server;
  private String baseUrl;
  private final List<Map<String, String>> tokenRequests = new CopyOnWriteArrayList<>();
  private final AtomicInteger pollCount = new AtomicInteger();
  private volatile String finalTokenResponse;

  @Before
  public void startServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    server.createContext("/login/device/code", exchange -> {
      Map<String, String> form = readForm(exchange);
      Assert.assertEquals("test-client", form.get("client_id"));
      respond(exchange, "{\"device_code\":\"dev-123\",\"user_code\":\"ABCD-1234\","
          + "\"verification_uri\":\"https://github.com/login/device\","
          + "\"expires_in\":900,\"interval\":1}");
    });
    server.createContext("/login/oauth/access_token", exchange -> {
      Map<String, String> form = readForm(exchange);
      tokenRequests.add(form);
      if ("refresh_token".equals(form.get("grant_type"))) {
        respond(exchange, "{\"access_token\":\"gho_refreshed\",\"token_type\":\"bearer\","
            + "\"expires_in\":28800}");
        return;
      }
      int poll = pollCount.incrementAndGet();
      if (poll == 1) {
        respond(exchange, "{\"error\":\"authorization_pending\"}");
      } else if (poll == 2) {
        respond(exchange, "{\"error\":\"slow_down\",\"interval\":1}");
      } else {
        respond(exchange, finalTokenResponse);
      }
    });
    server.createContext("/user", exchange -> {
      Assert.assertEquals("Bearer gho_token",
          exchange.getRequestHeaders().getFirst("Authorization"));
      respond(exchange, "{\"login\":\"octocat\"}");
    });
    server.start();
    baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    finalTokenResponse = "{\"access_token\":\"gho_token\",\"token_type\":\"bearer\","
        + "\"scope\":\"read:user,user:email\",\"refresh_token\":\"ghr_refresh\","
        + "\"expires_in\":28800,\"refresh_token_expires_in\":15811200}";
  }

  @After
  public void stopServer() {
    server.stop(0);
  }

  private static Map<String, String> readForm(HttpExchange exchange) throws IOException {
    String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    Map<String, String> form = new HashMap<>();
    for (String pair : body.split("&")) {
      String[] parts = pair.split("=", 2);
      form.put(URLDecoder.decode(parts[0], StandardCharsets.UTF_8),
          parts.length > 1 ? URLDecoder.decode(parts[1], StandardCharsets.UTF_8) : "");
    }
    return form;
  }

  private static void respond(HttpExchange exchange, String json) throws IOException {
    byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(200, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private GitHubDeviceCodeAuthenticator authenticator() {
    return new GitHubDeviceCodeAuthenticator(
        "test-client", baseUrl, baseUrl, HttpClient.newHttpClient());
  }

  @Test
  public void deviceFlowPollsUntilTheTokenIsIssued() throws Exception {
    GitHubDeviceCodeAuthenticator authenticator = authenticator();
    DeviceCode code = authenticator.requestDeviceCode(null);
    Assert.assertEquals("ABCD-1234", code.userCode);
    Assert.assertEquals("https://github.com/login/device", code.verificationUri);

    GitHubToken token = authenticator.pollForToken(code, null);
    Assert.assertEquals("gho_token", token.accessToken);
    Assert.assertEquals("ghr_refresh", token.refreshToken);
    Assert.assertEquals(28800, token.expiresIn);
    Assert.assertEquals(3, pollCount.get());
    Assert.assertEquals("dev-123", tokenRequests.get(0).get("device_code"));
    Assert.assertEquals("urn:ietf:params:oauth:grant-type:device_code",
        tokenRequests.get(0).get("grant_type"));

    Assert.assertEquals("octocat", authenticator.getUserLogin(token.accessToken));
  }

  @Test
  public void deniedAccessIsReported() throws Exception {
    finalTokenResponse = "{\"error\":\"access_denied\","
        + "\"error_description\":\"The user has denied your application access.\"}";
    GitHubDeviceCodeAuthenticator authenticator = authenticator();
    DeviceCode code = authenticator.requestDeviceCode(null);
    try {
      authenticator.pollForToken(code, null);
      Assert.fail("Expected access to be denied.");
    } catch (GitHubAuthenticationException e) {
      Assert.assertEquals("access_denied", e.getError());
    }
  }

  @Test
  public void refreshTokenIsExchanged() throws Exception {
    GitHubToken token = authenticator().refreshToken("ghr_refresh");
    Assert.assertEquals("gho_refreshed", token.accessToken);
    Map<String, String> request = tokenRequests.get(0);
    Assert.assertEquals("refresh_token", request.get("grant_type"));
    Assert.assertEquals("ghr_refresh", request.get("refresh_token"));
  }

  @Test
  public void credentialStoreRoundTripsAndRestrictsPermissions() throws Exception {
    Path directory = Files.createTempDirectory("devtunnels-test");
    try {
      CredentialStore store = new CredentialStore(directory.resolve("sub/credentials.json"));
      Assert.assertNull(store.load("prod"));

      CredentialStore.Credentials credentials = new CredentialStore.Credentials();
      credentials.provider = "github";
      credentials.accessToken = "gho_secret";
      credentials.userName = "octocat";
      store.save("prod", credentials);

      CredentialStore.Credentials loaded = store.load("prod");
      Assert.assertEquals("gho_secret", loaded.accessToken);
      Assert.assertEquals("octocat", loaded.userName);
      Assert.assertNull(store.load("ppe"));
      if (directory.getFileSystem().supportedFileAttributeViews().contains("posix")) {
        Assert.assertEquals("rw-------", PosixFilePermissions.toString(
            Files.getPosixFilePermissions(store.getFile())));
      }

      store.save("prod", null);
      Assert.assertNull(store.load("prod"));
    } finally {
      try (var paths = Files.walk(directory)) {
        paths.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
      }
    }
  }
}

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.auth;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.google.gson.annotations.SerializedName;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

/**
 * Signs in to GitHub with the OAuth device authorization flow (RFC 8628).
 *
 * <p>The user is shown a short code and a verification URL. They open the URL in any browser
 * (on any device), enter the code and approve access; meanwhile this class polls GitHub until
 * the access token is issued. The resulting token is sent to the tunnel service in an
 * {@code Authorization: github <token>} header.</p>
 *
 * @see <a href="https://docs.github.com/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app#using-the-device-flow-to-generate-a-user-access-token">GitHub device flow</a>
 */
public class GitHubDeviceCodeAuthenticator {
  /** Default GitHub web host. */
  public static final String DEFAULT_GITHUB_URL = "https://github.com";
  /** Default GitHub API host. */
  public static final String DEFAULT_GITHUB_API_URL = "https://api.github.com";
  /** Scopes requested by default; the tunnel service needs the user's identity and email. */
  public static final String DEFAULT_SCOPES = "read:user user:email";

  private static final String DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
  private static final Gson gson = new Gson();

  private final String clientId;
  private final String gitHubUrl;
  private final String gitHubApiUrl;
  private final HttpClient httpClient;

  /** A device code issued by GitHub, with the user code to show to the user. */
  public static class DeviceCode {
    @SerializedName("device_code")
    public String deviceCode;
    @SerializedName("user_code")
    public String userCode;
    @SerializedName("verification_uri")
    public String verificationUri;
    @SerializedName("expires_in")
    public int expiresIn;
    @SerializedName("interval")
    public int interval;
  }

  /** An access token issued by GitHub. */
  public static class GitHubToken {
    @SerializedName("access_token")
    public String accessToken;
    @SerializedName("token_type")
    public String tokenType;
    @SerializedName("scope")
    public String scope;
    @SerializedName("refresh_token")
    public String refreshToken;
    /** Seconds until the access token expires, or 0 if it does not expire. */
    @SerializedName("expires_in")
    public long expiresIn;
    @SerializedName("refresh_token_expires_in")
    public long refreshTokenExpiresIn;
  }

  /** Thrown when GitHub returns an OAuth error. */
  public static class GitHubAuthenticationException extends IOException {
    private final String error;

    /**
     * Creates an exception for an OAuth error code and optional description.
     */
    public GitHubAuthenticationException(String error, String description) {
      super(description != null && !description.isEmpty()
          ? error + ": " + description : error);
      this.error = error;
    }

    /** The OAuth error code, e.g. "expired_token" or "access_denied". */
    public String getError() {
      return error;
    }
  }

  public GitHubDeviceCodeAuthenticator(String clientId) {
    this(clientId, DEFAULT_GITHUB_URL, DEFAULT_GITHUB_API_URL, HttpClient.newHttpClient());
  }

  /**
   * Creates an authenticator.
   *
   * @param clientId     Client ID of the GitHub app (see
   *                     {@code TunnelServiceProperties.gitHubAppClientId}).
   * @param gitHubUrl    GitHub web URL, for GitHub Enterprise or tests.
   * @param gitHubApiUrl GitHub API URL, for GitHub Enterprise or tests.
   * @param httpClient   HTTP client to use.
   */
  public GitHubDeviceCodeAuthenticator(
      String clientId, String gitHubUrl, String gitHubApiUrl, HttpClient httpClient) {
    if (clientId == null || clientId.isBlank()) {
      throw new IllegalArgumentException("A GitHub app client ID is required.");
    }
    this.clientId = clientId;
    this.gitHubUrl = stripTrailingSlash(gitHubUrl);
    this.gitHubApiUrl = stripTrailingSlash(gitHubApiUrl);
    this.httpClient = httpClient;
  }

  private static String stripTrailingSlash(String url) {
    return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
  }

  /**
   * Starts the device flow by requesting a device code and user code.
   */
  public DeviceCode requestDeviceCode(String scopes) throws IOException, InterruptedException {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("client_id", clientId);
    form.put("scope", scopes != null ? scopes : DEFAULT_SCOPES);
    JsonObject json = postForm(gitHubUrl + "/login/device/code", form);
    DeviceCode code = gson.fromJson(json, DeviceCode.class);
    if (code.deviceCode == null || code.userCode == null) {
      throw new IOException("GitHub did not return a device code.");
    }
    if (code.interval <= 0) {
      code.interval = 5;
    }
    return code;
  }

  /**
   * Polls GitHub until the user approves (or denies) the device code, or it expires.
   *
   * @param code      Device code from {@link #requestDeviceCode}.
   * @param onWaiting Called before each poll with the seconds remaining, or null.
   * @return The access token.
   * @throws GitHubAuthenticationException if the user denied access or the code expired.
   */
  public GitHubToken pollForToken(DeviceCode code, Consumer<Long> onWaiting)
      throws IOException, InterruptedException {
    Instant deadline = Instant.now().plusSeconds(code.expiresIn > 0 ? code.expiresIn : 900);
    long intervalSeconds = code.interval;
    while (Instant.now().isBefore(deadline)) {
      if (onWaiting != null) {
        onWaiting.accept(Duration.between(Instant.now(), deadline).getSeconds());
      }
      Thread.sleep(intervalSeconds * 1000);

      Map<String, String> form = new LinkedHashMap<>();
      form.put("client_id", clientId);
      form.put("device_code", code.deviceCode);
      form.put("grant_type", DEVICE_GRANT_TYPE);
      JsonObject json = postForm(gitHubUrl + "/login/oauth/access_token", form);
      if (json.has("access_token")) {
        return gson.fromJson(json, GitHubToken.class);
      }
      String error = json.has("error") ? json.get("error").getAsString() : "unknown_error";
      switch (error) {
        case "authorization_pending":
          break;
        case "slow_down":
          // RFC 8628: increase the interval by 5 seconds (GitHub also returns the new value).
          intervalSeconds = json.has("interval")
              ? json.get("interval").getAsLong() : intervalSeconds + 5;
          break;
        default:
          throw new GitHubAuthenticationException(error, json.has("error_description")
              ? json.get("error_description").getAsString() : null);
      }
    }
    throw new GitHubAuthenticationException("expired_token", "The device code has expired.");
  }

  /**
   * Exchanges a refresh token for a new access token (for apps with expiring user tokens).
   */
  public GitHubToken refreshToken(String refreshToken) throws IOException, InterruptedException {
    Map<String, String> form = new LinkedHashMap<>();
    form.put("client_id", clientId);
    form.put("grant_type", "refresh_token");
    form.put("refresh_token", refreshToken);
    JsonObject json = postForm(gitHubUrl + "/login/oauth/access_token", form);
    if (!json.has("access_token")) {
      String error = json.has("error") ? json.get("error").getAsString() : "unknown_error";
      throw new GitHubAuthenticationException(error, json.has("error_description")
          ? json.get("error_description").getAsString() : null);
    }
    return gson.fromJson(json, GitHubToken.class);
  }

  /**
   * Gets the login name of the user that owns the token.
   */
  public String getUserLogin(String accessToken) throws IOException, InterruptedException {
    HttpRequest request = HttpRequest.newBuilder(URI.create(gitHubApiUrl + "/user"))
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", "Bearer " + accessToken)
        .header("User-Agent", "devibetunnel")
        .GET()
        .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != 200) {
      throw new IOException("GitHub user request failed: HTTP " + response.statusCode());
    }
    JsonObject json = gson.fromJson(response.body(), JsonObject.class);
    return json.has("login") ? json.get("login").getAsString() : null;
  }

  private JsonObject postForm(String url, Map<String, String> form)
      throws IOException, InterruptedException {
    String body = form.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
            + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));
    HttpRequest request = HttpRequest.newBuilder(URI.create(url))
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "devibetunnel")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    JsonObject json;
    try {
      json = gson.fromJson(response.body(), JsonObject.class);
    } catch (RuntimeException e) {
      json = null;
    }
    if (json == null) {
      throw new IOException("Unexpected response from GitHub: HTTP " + response.statusCode());
    }
    if (response.statusCode() >= 400 && !json.has("error")) {
      throw new IOException("GitHub request failed: HTTP " + response.statusCode());
    }
    return json;
  }
}

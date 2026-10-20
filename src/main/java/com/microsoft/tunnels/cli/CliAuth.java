// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.cli;

import com.microsoft.tunnels.auth.CredentialStore;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator.DeviceCode;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator.GitHubAuthenticationException;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator.GitHubToken;
import com.microsoft.tunnels.contracts.TunnelAuthenticationSchemes;
import com.microsoft.tunnels.contracts.TunnelServiceProperties;

import java.io.IOException;
import java.io.PrintStream;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;
import java.util.function.Supplier;

/**
 * Resolves how the CLI authenticates to the tunnel service, and implements the user
 * login/logout commands.
 *
 * <p>User credentials are taken from the first of: {@code --user-token} (a full Authorization
 * header value), {@code --github-token}, {@code --aad-token}, the matching
 * {@code DEVTUNNEL_*} environment variables, or the credentials saved by
 * {@code user login} (GitHub device code). A tunnel access token ({@code --access-token} or
 * {@code DEVIBETUNNEL_ACCESS_TOKEN}) can be used instead of, or in addition to, user
 * credentials for operations on a single tunnel.</p>
 */
final class CliAuth {
  private static final String GITHUB_PROVIDER = "github";
  private static final long EXPIRY_MARGIN_SECONDS = 120;

  private final CommandLine commandLine;
  private final String environment;
  private final TunnelServiceProperties serviceProperties;
  private final CredentialStore store;
  private final PrintStream out;
  private String resolvedHeader;
  private String resolvedSource;
  private boolean resolved;

  CliAuth(
      CommandLine commandLine,
      String environment,
      TunnelServiceProperties serviceProperties,
      CredentialStore store,
      PrintStream out) {
    this.commandLine = commandLine;
    this.environment = environment;
    this.serviceProperties = serviceProperties;
    this.store = store;
    this.out = out;
  }

  private static String env(String name) {
    String value = System.getenv(name);
    return value != null && !value.isBlank() ? value.trim() : null;
  }

  /** The tunnel access token given on the command line or environment, or null. */
  String getTunnelAccessToken() {
    String token = commandLine.get("--access-token");
    if (token == null) {
      token = env("DEVIBETUNNEL_ACCESS_TOKEN");
    }
    if (token != null && token.toLowerCase().startsWith(
        TunnelAuthenticationSchemes.tunnel.toLowerCase() + " ")) {
      token = token.substring(TunnelAuthenticationSchemes.tunnel.length() + 1).trim();
    }
    return token;
  }

  /** The user token callback for the management client. */
  Supplier<CompletableFuture<String>> userTokenCallback() {
    return () -> CompletableFuture.supplyAsync(() -> {
      try {
        return getUserAuthorizationHeader();
      } catch (IOException e) {
        throw new IllegalStateException(e.getMessage(), e);
      }
    });
  }

  /** Describes where the user credentials come from, or null if there are none. */
  synchronized String describeSource() throws IOException {
    getUserAuthorizationHeader();
    return resolvedSource;
  }

  /**
   * Gets the Authorization header value for user credentials, or null if there are none.
   */
  synchronized String getUserAuthorizationHeader() throws IOException {
    if (resolved) {
      return resolvedHeader;
    }
    resolved = true;
    String value;
    if ((value = commandLine.get("--user-token")) != null) {
      return resolve(value, "--user-token");
    }
    if ((value = commandLine.get("--github-token")) != null) {
      return resolve(TunnelAuthenticationSchemes.gitHub + " " + value, "--github-token");
    }
    if ((value = commandLine.get("--aad-token")) != null) {
      return resolve("Bearer " + value, "--aad-token");
    }
    if ((value = env("DEVIBETUNNEL_USER_TOKEN")) != null) {
      return resolve(value, "DEVIBETUNNEL_USER_TOKEN");
    }
    if ((value = env("DEVIBETUNNEL_GITHUB_TOKEN")) != null) {
      return resolve(TunnelAuthenticationSchemes.gitHub + " " + value, "DEVIBETUNNEL_GITHUB_TOKEN");
    }
    if ((value = env("DEVIBETUNNEL_AAD_TOKEN")) != null) {
      return resolve("Bearer " + value, "DEVIBETUNNEL_AAD_TOKEN");
    }

    CredentialStore.Credentials credentials = store.load(environment);
    if (credentials == null || credentials.accessToken == null) {
      return resolve(null, null);
    }
    long now = Instant.now().getEpochSecond();
    if (credentials.expiresAt > 0 && now >= credentials.expiresAt - EXPIRY_MARGIN_SECONDS) {
      credentials = refresh(credentials);
    }
    String user = credentials.userName != null ? " as " + credentials.userName : "";
    return resolve(
        TunnelAuthenticationSchemes.gitHub + " " + credentials.accessToken,
        "GitHub login" + user);
  }

  private String resolve(String header, String source) {
    resolvedHeader = header;
    resolvedSource = source;
    return header;
  }

  private CredentialStore.Credentials refresh(CredentialStore.Credentials credentials)
      throws IOException {
    long now = Instant.now().getEpochSecond();
    boolean refreshable = credentials.refreshToken != null
        && (credentials.refreshTokenExpiresAt == 0 || now < credentials.refreshTokenExpiresAt);
    if (!refreshable) {
      throw new IOException("Your GitHub login has expired. Run 'user login' to sign in again.");
    }
    try {
      GitHubToken token = createAuthenticator().refreshToken(credentials.refreshToken);
      CredentialStore.Credentials refreshed = toCredentials(token, credentials.userName);
      store.save(environment, refreshed);
      return refreshed;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while refreshing the GitHub login.", e);
    } catch (GitHubAuthenticationException e) {
      throw new IOException("Your GitHub login has expired (" + e.getError()
          + "). Run 'user login' to sign in again.", e);
    }
  }

  private GitHubDeviceCodeAuthenticator createAuthenticator() {
    return new GitHubDeviceCodeAuthenticator(serviceProperties.gitHubAppClientId);
  }

  private static CredentialStore.Credentials toCredentials(GitHubToken token, String userName) {
    long now = Instant.now().getEpochSecond();
    CredentialStore.Credentials credentials = new CredentialStore.Credentials();
    credentials.provider = GITHUB_PROVIDER;
    credentials.accessToken = token.accessToken;
    credentials.refreshToken = token.refreshToken;
    credentials.expiresAt = token.expiresIn > 0 ? now + token.expiresIn : 0;
    credentials.refreshTokenExpiresAt =
        token.refreshTokenExpiresIn > 0 ? now + token.refreshTokenExpiresIn : 0;
    credentials.userName = userName;
    return credentials;
  }

  /**
   * Signs in with the GitHub device code flow and saves the credentials.
   */
  void login(String scopes) throws IOException, InterruptedException {
    GitHubDeviceCodeAuthenticator authenticator = createAuthenticator();
    DeviceCode code = authenticator.requestDeviceCode(scopes);
    out.println("To sign in with GitHub, open " + code.verificationUri
        + " in a browser and enter the code:");
    out.println();
    out.println("    " + code.userCode);
    out.println();
    out.println("Waiting for authorization (the code expires in "
        + (code.expiresIn / 60) + " minutes)...");

    GitHubToken token = authenticator.pollForToken(code, null);
    String userName = null;
    try {
      userName = authenticator.getUserLogin(token.accessToken);
    } catch (IOException e) {
      // The login name is informational only.
    }
    store.save(environment, toCredentials(token, userName));
    synchronized (this) {
      resolved = false;
    }
    out.println("Logged in" + (userName != null ? " as " + userName : "")
        + " using GitHub.");
  }

  void logout() throws IOException {
    if (store.load(environment) == null) {
      out.println("Not logged in.");
      return;
    }
    store.save(environment, null);
    out.println("Logged out.");
  }

  void show() throws IOException {
    String source = describeSource();
    if (source == null) {
      String accessToken = getTunnelAccessToken();
      out.println(accessToken != null
          ? "Not logged in; using a tunnel access token."
          : "Not logged in. Run 'user login' to sign in with GitHub.");
      return;
    }
    out.println("Authenticated via " + source + ".");
    CredentialStore.Credentials credentials = store.load(environment);
    if (credentials != null && source.startsWith("GitHub login") && credentials.expiresAt > 0) {
      out.println("Token expires: " + Instant.ofEpochSecond(credentials.expiresAt));
    }
  }
}

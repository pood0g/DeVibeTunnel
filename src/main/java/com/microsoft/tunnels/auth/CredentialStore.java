// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.HashMap;
import java.util.Map;

/**
 * Persists user login credentials in a JSON file readable only by the current user.
 *
 * <p>Credentials are keyed by tunnel service environment (e.g. "prod"). The default location
 * is {@code ~/.devibetunnel/credentials.json}; set {@code DEVIBETUNNEL_HOME} to use a
 * different directory.</p>
 */
public class CredentialStore {
  private static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

  private final Path file;

  /** Saved credentials for one environment. */
  public static class Credentials {
    /** Identity provider, e.g. "github". */
    public String provider;
    public String accessToken;
    public String refreshToken;
    /** Access token expiry in epoch seconds, or 0 if it does not expire. */
    public long expiresAt;
    /** Refresh token expiry in epoch seconds, or 0 if unknown or it does not expire. */
    public long refreshTokenExpiresAt;
    public String userName;
  }

  private static class FileContents {
    Map<String, Credentials> environments = new HashMap<>();
  }

  public CredentialStore(Path file) {
    this.file = file;
  }

  /**
   * Creates a store at the default location.
   */
  public static CredentialStore createDefault() {
    String home = System.getenv("DEVIBETUNNEL_HOME");
    Path directory = home != null && !home.isBlank()
        ? Paths.get(home)
        : Paths.get(System.getProperty("user.home"), ".devibetunnel");
    return new CredentialStore(directory.resolve("credentials.json"));
  }

  public Path getFile() {
    return file;
  }

  /**
   * Loads the credentials for an environment.
   *
   * @return The credentials, or null if none are saved.
   */
  public Credentials load(String environment) throws IOException {
    return read().environments.get(environment);
  }

  /**
   * Saves (or with null, removes) the credentials for an environment.
   */
  public synchronized void save(String environment, Credentials credentials) throws IOException {
    FileContents contents = read();
    if (credentials == null) {
      if (contents.environments.remove(environment) == null) {
        return;
      }
    } else {
      contents.environments.put(environment, credentials);
    }
    write(contents);
  }

  private FileContents read() throws IOException {
    if (!Files.exists(file)) {
      return new FileContents();
    }
    String json = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
    FileContents contents = gson.fromJson(json, FileContents.class);
    if (contents == null) {
      contents = new FileContents();
    }
    if (contents.environments == null) {
      contents.environments = new HashMap<>();
    }
    return contents;
  }

  private void write(FileContents contents) throws IOException {
    Path directory = file.toAbsolutePath().getParent();
    Files.createDirectories(directory);
    setOwnerOnly(directory, "rwx------");
    Path temp = Files.createTempFile(directory, "credentials", ".tmp");
    try {
      // Restrict permissions before writing the secret.
      setOwnerOnly(temp, "rw-------");
      Files.write(temp, gson.toJson(contents).getBytes(StandardCharsets.UTF_8));
      Files.move(temp, file, StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
    } finally {
      Files.deleteIfExists(temp);
    }
  }

  private static void setOwnerOnly(Path path, String permissions) {
    try {
      Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(permissions));
    } catch (UnsupportedOperationException | IOException e) {
      // Not a POSIX file system (e.g. Windows); rely on the user profile's ACLs.
    }
  }
}

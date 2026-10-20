// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.cli;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.microsoft.tunnels.auth.CredentialStore;
import com.microsoft.tunnels.auth.GitHubDeviceCodeAuthenticator;
import com.microsoft.tunnels.cli.CommandLine.UsageException;
import com.microsoft.tunnels.connections.ForwardedPort;
import com.microsoft.tunnels.connections.ForwardedPortEventListener;
import com.microsoft.tunnels.connections.TunnelHostListener;
import com.microsoft.tunnels.connections.TunnelRelayTunnelClient;
import com.microsoft.tunnels.connections.TunnelRelayTunnelHost;
import com.microsoft.tunnels.contracts.ClusterDetails;
import com.microsoft.tunnels.contracts.ClusterRecommendation;
import com.microsoft.tunnels.contracts.ClusterRecommendationResponse;
import com.microsoft.tunnels.contracts.NamedRateStatus;
import com.microsoft.tunnels.contracts.ProblemDetails;
import com.microsoft.tunnels.contracts.Tunnel;
import com.microsoft.tunnels.contracts.TunnelAccessControl;
import com.microsoft.tunnels.contracts.TunnelAccessControlEntry;
import com.microsoft.tunnels.contracts.TunnelAccessControlEntryType;
import com.microsoft.tunnels.contracts.TunnelAccessScopes;
import com.microsoft.tunnels.contracts.TunnelContracts;
import com.microsoft.tunnels.contracts.TunnelEndpoint;
import com.microsoft.tunnels.contracts.TunnelPort;
import com.microsoft.tunnels.contracts.TunnelServiceProperties;
import com.microsoft.tunnels.management.HttpResponseException;
import com.microsoft.tunnels.management.ProductHeaderValue;
import com.microsoft.tunnels.management.TunnelManagementClient;
import com.microsoft.tunnels.management.TunnelRequestOptions;

import java.io.PrintStream;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * DeVibeTunnel command-line interface for Microsoft dev tunnels, runnable as a standalone jar:
 * {@code java -jar devibetunnel.jar <command> [options]}.
 */
public final class DeVibeTunnelCli {
  static final Set<String> GLOBAL_OPTIONS = Set.of(
      "--verbose", "--help", "--env", "--service-uri", "--json", "--access-token",
      "--user-token", "--github-token", "--aad-token", "--version");

  private static final String PRODUCT_NAME = "devibetunnel";
  private static final String VERSION = DeVibeTunnelCli.class.getPackage()
      .getImplementationVersion() != null
      ? DeVibeTunnelCli.class.getPackage().getImplementationVersion() : "dev";
  private static final Pattern CLUSTER_ID = Pattern.compile("[a-z]{2,8}[0-9]*");
  private static final int EXIT_OK = 0;
  private static final int EXIT_ERROR = 1;
  private static final int EXIT_USAGE = 2;

  private final PrintStream out;
  private final PrintStream err;
  private CommandLine commandLine;
  private String environment;
  private TunnelServiceProperties serviceProperties;
  private CliAuth auth;
  private TunnelManagementClient managementClient;
  private Gson json;

  DeVibeTunnelCli(PrintStream out, PrintStream err) {
    this.out = out;
    this.err = err;
  }

  /**
   * Entry point.
   */
  public static void main(String[] args) {
    int exitCode = new DeVibeTunnelCli(System.out, System.err).run(args);
    System.exit(exitCode);
  }

  int run(String[] args) {
    try {
      commandLine = CommandLine.parse(args);
    } catch (UsageException e) {
      err.println("Error: " + e.getMessage());
      return EXIT_USAGE;
    }
    configureLogging(commandLine.flag("--verbose"));

    if (commandLine.flag("--version")) {
      out.println(PRODUCT_NAME + " " + VERSION);
      return EXIT_OK;
    }
    String command = commandLine.shift();
    if (command == null || command.equals("help") || commandLine.flag("--help")) {
      printHelp();
      return command == null && !commandLine.flag("--help") ? EXIT_USAGE : EXIT_OK;
    }

    try {
      initialize();
      return dispatch(command);
    } catch (UsageException e) {
      err.println("Error: " + e.getMessage());
      err.println("Run with --help for usage.");
      return EXIT_USAGE;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      err.println("Interrupted.");
      return EXIT_ERROR;
    } catch (Exception e) {
      err.println("Error: " + describeError(e));
      if (commandLine.flag("--verbose")) {
        e.printStackTrace(err);
      }
      return EXIT_ERROR;
    }
  }

  private void initialize() {
    environment = commandLine.get("--env", System.getenv("DEVIBETUNNEL_ENV"));
    if (environment == null || environment.isBlank()) {
      environment = "prod";
    }
    try {
      serviceProperties = TunnelServiceProperties.environment(
          environment.toLowerCase(Locale.ROOT));
    } catch (IllegalArgumentException e) {
      throw new UsageException("Unknown environment '" + environment
          + "'. Use prod, ppe, dev or local.");
    }
    auth = new CliAuth(commandLine, environment.toLowerCase(Locale.ROOT), serviceProperties,
        CredentialStore.createDefault(), out);
    String serviceUri = commandLine.get("--service-uri", serviceProperties.serviceUri);
    managementClient = new TunnelManagementClient(
        new ProductHeaderValue[] {new ProductHeaderValue(PRODUCT_NAME, VERSION)},
        auth.userTokenCallback(),
        serviceUri,
        TunnelManagementClient.ApiVersions[0]);
    json = TunnelContracts.getGson().newBuilder().setPrettyPrinting().create();
  }

  private int dispatch(String command) throws Exception {
    switch (command) {
      case "user":
        return userCommand();
      case "login":
        return userCommand("login");
      case "logout":
        return userCommand("logout");
      case "list":
        return listTunnels();
      case "show":
        return showTunnel();
      case "create":
        return createTunnel();
      case "update":
        return updateTunnel();
      case "delete":
        return deleteTunnel();
      case "port":
        return portCommand();
      case "access":
        return accessCommand();
      case "token":
        return getToken();
      case "host":
        return host();
      case "connect":
        return connect();
      case "clusters":
        return listClusters();
      case "limits":
        return listLimits();
      case "check-name":
        return checkName();
      default:
        throw new UsageException("Unknown command: " + command);
    }
  }

  // ---------------------------------------------------------------------------------------
  // User commands

  private int userCommand() throws Exception {
    String subcommand = commandLine.shift();
    if (subcommand == null) {
      throw new UsageException("Specify a user command: login, logout or show.");
    }
    return userCommand(subcommand);
  }

  private int userCommand(String subcommand) throws Exception {
    switch (subcommand) {
      case "login":
        commandLine.allowOnly(Set.of("--github", "--device-code", "--scopes"));
        commandLine.maxPositionals(0);
        auth.login(commandLine.get("--scopes", GitHubDeviceCodeAuthenticator.DEFAULT_SCOPES));
        return EXIT_OK;
      case "logout":
        commandLine.allowOnly(Set.of());
        auth.logout();
        return EXIT_OK;
      case "show":
        commandLine.allowOnly(Set.of());
        auth.show();
        return EXIT_OK;
      default:
        throw new UsageException("Unknown user command: " + subcommand);
    }
  }

  // ---------------------------------------------------------------------------------------
  // Tunnel commands

  private TunnelRequestOptions options() {
    TunnelRequestOptions options = new TunnelRequestOptions();
    options.accessToken = auth.getTunnelAccessToken();
    return options;
  }

  private Tunnel requireTunnelReference() {
    String reference = commandLine.shift();
    if (reference == null) {
      throw new UsageException("A tunnel ID is required.");
    }
    return parseTunnelReference(reference, commandLine.get("--cluster"));
  }

  /**
   * Parses "tunnelId.clusterId" (as shown by list), or a tunnel ID with --cluster, or a
   * tunnel name.
   */
  static Tunnel parseTunnelReference(String reference, String clusterId) {
    Tunnel tunnel = new Tunnel();
    if (clusterId != null) {
      tunnel.tunnelId = reference;
      tunnel.clusterId = clusterId;
      return tunnel;
    }
    int dot = reference.lastIndexOf('.');
    if (dot > 0 && dot < reference.length() - 1
        && CLUSTER_ID.matcher(reference.substring(dot + 1)).matches()) {
      tunnel.tunnelId = reference.substring(0, dot);
      tunnel.clusterId = reference.substring(dot + 1);
    } else {
      tunnel.name = reference;
    }
    return tunnel;
  }

  static String formatTunnelId(Tunnel tunnel) {
    if (tunnel.tunnelId != null && tunnel.clusterId != null) {
      return tunnel.tunnelId + "." + tunnel.clusterId;
    }
    return tunnel.tunnelId != null ? tunnel.tunnelId : tunnel.name;
  }

  private Tunnel getTunnelOrThrow(Tunnel reference, TunnelRequestOptions options) {
    Tunnel tunnel = managementClient.getTunnelAsync(reference, options).join();
    if (tunnel == null) {
      throw new IllegalStateException("Tunnel not found: " + formatTunnelId(reference));
    }
    return tunnel;
  }

  private int listTunnels() {
    commandLine.allowOnly(Set.of("--cluster", "--labels", "--all-labels", "--limit", "--domain"));
    commandLine.maxPositionals(0);
    TunnelRequestOptions options = options();
    options.includePorts = true;
    List<String> labels = commandLine.getAll("--labels");
    if (!labels.isEmpty()) {
      options.labels = labels;
      options.requireAllLabels = commandLine.flag("--all-labels");
    }
    options.limit = commandLine.getInt("--limit");
    Collection<Tunnel> tunnels = managementClient.listTunnelsAsync(
        commandLine.get("--cluster"), commandLine.get("--domain"), options).join();
    if (commandLine.flag("--json")) {
      out.println(json.toJson(tunnels));
      return EXIT_OK;
    }
    if (tunnels == null || tunnels.isEmpty()) {
      out.println("No tunnels found.");
      return EXIT_OK;
    }
    Table table = new Table("Tunnel ID", "Host Connections", "Ports", "Labels", "Expiration",
        "Description");
    for (Tunnel tunnel : tunnels) {
      table.add(
          formatTunnelId(tunnel),
          tunnel.status != null && tunnel.status.hostConnectionCount != null
              ? String.valueOf(tunnel.status.hostConnectionCount.current) : "0",
          tunnel.ports != null ? String.valueOf(tunnel.ports.length) : "0",
          tunnel.labels != null ? String.join(", ", tunnel.labels) : "",
          tunnel.expiration != null ? tunnel.expiration.toInstant().toString() : "",
          tunnel.description != null ? tunnel.description : "");
    }
    table.print(out);
    out.println();
    out.println("Found " + tunnels.size() + " tunnel(s).");
    return EXIT_OK;
  }

  private int showTunnel() {
    commandLine.allowOnly(Set.of("--cluster"));
    Tunnel reference = requireTunnelReference();
    commandLine.maxPositionals(0);
    TunnelRequestOptions options = options();
    options.includePorts = true;
    options.includeAccessControl = true;
    Tunnel tunnel = getTunnelOrThrow(reference, options);
    if (commandLine.flag("--json")) {
      out.println(json.toJson(tunnel));
      return EXIT_OK;
    }
    printTunnel(tunnel);
    return EXIT_OK;
  }

  private void printTunnel(Tunnel tunnel) {
    out.println("Tunnel ID             : " + formatTunnelId(tunnel));
    if (tunnel.name != null) {
      out.println("Name                  : " + tunnel.name);
    }
    if (tunnel.description != null) {
      out.println("Description           : " + tunnel.description);
    }
    if (tunnel.labels != null && tunnel.labels.length > 0) {
      out.println("Labels                : " + String.join(", ", tunnel.labels));
    }
    if (tunnel.status != null) {
      if (tunnel.status.hostConnectionCount != null) {
        out.println("Host connections      : " + tunnel.status.hostConnectionCount.current);
      }
      if (tunnel.status.clientConnectionCount != null) {
        out.println("Client connections    : " + tunnel.status.clientConnectionCount.current);
      }
    }
    if (tunnel.created != null) {
      out.println("Created               : " + tunnel.created.toInstant());
    }
    if (tunnel.expiration != null) {
      out.println("Expiration            : " + tunnel.expiration.toInstant());
    }
    printAccessControl(tunnel.accessControl, "Access control        : ");
    int portCount = tunnel.ports != null ? tunnel.ports.length : 0;
    out.println("Ports                 : " + portCount);
    if (tunnel.ports != null) {
      for (TunnelPort port : tunnel.ports) {
        out.println("  " + port.portNumber + "  " + (port.protocol != null ? port.protocol : "auto")
            + (port.description != null ? "  " + port.description : ""));
        for (String uri : getPortUris(tunnel, port)) {
          out.println("      " + uri);
        }
      }
    }
  }

  private void printAccessControl(TunnelAccessControl accessControl, String heading) {
    if (accessControl == null || accessControl.entries == null
        || accessControl.entries.length == 0) {
      out.println(heading + "(none)");
      return;
    }
    out.println(heading);
    for (TunnelAccessControlEntry entry : accessControl.entries) {
      out.println("  " + describeAccessControlEntry(entry));
    }
  }

  private static String describeAccessControlEntry(TunnelAccessControlEntry entry) {
    StringBuilder text = new StringBuilder();
    text.append(entry.isDeny ? "-" : "+");
    text.append(entry.type);
    if (entry.provider != null) {
      text.append(" (").append(entry.provider).append(")");
    }
    if (entry.subjects != null && entry.subjects.length > 0) {
      text.append(" [").append(String.join(", ", entry.subjects)).append("]");
    }
    text.append(" scopes: ").append(
        entry.scopes != null ? String.join(", ", entry.scopes) : "");
    if (entry.isInherited) {
      text.append(" (inherited)");
    }
    return text.toString();
  }

  private static List<String> getPortUris(Tunnel tunnel, TunnelPort port) {
    List<String> uris = new ArrayList<>();
    if (port.portForwardingUris != null && port.portForwardingUris.length > 0) {
      uris.addAll(Arrays.asList(port.portForwardingUris));
    } else if (tunnel.endpoints != null) {
      for (TunnelEndpoint endpoint : tunnel.endpoints) {
        URI uri = TunnelEndpoint.getPortUri(endpoint, port.portNumber);
        if (uri != null && !uris.contains(uri.toString())) {
          uris.add(uri.toString());
        }
      }
    }
    return uris;
  }

  private static TunnelAccessControlEntry anonymousEntry(List<String> scopes) {
    TunnelAccessControlEntry entry = new TunnelAccessControlEntry();
    entry.type = TunnelAccessControlEntryType.Anonymous;
    entry.subjects = new String[0];
    entry.scopes = scopes.toArray(new String[0]);
    return entry;
  }

  /**
   * Parses port arguments of the form "8080" or "8080:https".
   */
  private List<TunnelPort> parsePorts() {
    List<TunnelPort> ports = new ArrayList<>();
    String defaultProtocol = commandLine.get("--protocol");
    for (String value : commandLine.getAll("--port")) {
      String[] parts = value.split(":", 2);
      TunnelPort port = new TunnelPort();
      try {
        port.portNumber = Integer.parseInt(parts[0]);
      } catch (NumberFormatException e) {
        throw new UsageException("Invalid port: " + value);
      }
      if (port.portNumber < 1 || port.portNumber > 65535) {
        throw new UsageException("Invalid port number: " + port.portNumber);
      }
      port.protocol = parts.length > 1 ? parts[1] : defaultProtocol;
      ports.add(port);
    }
    return ports;
  }

  /**
   * Parses a duration such as "30d", "12h", "90m" or "3600s" (or plain seconds).
   */
  static int parseDurationSeconds(String value) {
    if (value == null || value.isEmpty()) {
      throw new UsageException("A duration is required.");
    }
    char unit = Character.toLowerCase(value.charAt(value.length() - 1));
    String number = Character.isDigit(unit) ? value : value.substring(0, value.length() - 1);
    long multiplier;
    switch (unit) {
      case 'd':
        multiplier = 86400;
        break;
      case 'h':
        multiplier = 3600;
        break;
      case 'm':
        multiplier = 60;
        break;
      case 's':
        multiplier = 1;
        break;
      default:
        if (!Character.isDigit(unit)) {
          throw new UsageException("Invalid duration unit in '" + value + "'. Use d, h, m or s.");
        }
        multiplier = 1;
    }
    try {
      long seconds = Long.parseLong(number) * multiplier;
      if (seconds <= 0 || seconds > Integer.MAX_VALUE) {
        throw new UsageException("Invalid duration: " + value);
      }
      return (int) seconds;
    } catch (NumberFormatException e) {
      throw new UsageException("Invalid duration: " + value);
    }
  }

  private int createTunnel() {
    commandLine.allowOnly(Set.of("--cluster", "--description", "--labels", "--allow-anonymous",
        "--expiration", "--port", "--protocol", "--name", "--geo"));
    String tunnelId = commandLine.shift();
    commandLine.maxPositionals(0);
    Tunnel tunnel = new Tunnel();
    tunnel.tunnelId = tunnelId;
    tunnel.name = commandLine.get("--name");
    tunnel.clusterId = commandLine.get("--cluster");
    tunnel.description = commandLine.get("--description");
    List<String> labels = commandLine.getAll("--labels");
    if (!labels.isEmpty()) {
      tunnel.labels = labels.toArray(new String[0]);
    }
    if (commandLine.has("--expiration")) {
      tunnel.customExpiration = parseDurationSeconds(commandLine.get("--expiration"));
    }
    if (commandLine.flag("--allow-anonymous")) {
      tunnel.accessControl = new TunnelAccessControl();
      tunnel.accessControl.entries = new TunnelAccessControlEntry[] {
          anonymousEntry(List.of(TunnelAccessScopes.connect))};
    }
    List<TunnelPort> ports = parsePorts();
    if (!ports.isEmpty()) {
      tunnel.ports = ports.toArray(new TunnelPort[0]);
    }
    TunnelRequestOptions options = options();
    options.includePorts = true;
    options.requiredGeo = commandLine.get("--geo");
    Tunnel created = managementClient.createTunnelAsync(tunnel, options).join();
    if (commandLine.flag("--json")) {
      out.println(json.toJson(created));
      return EXIT_OK;
    }
    out.println("Created tunnel: " + formatTunnelId(created));
    printTunnel(created);
    return EXIT_OK;
  }

  private int updateTunnel() {
    commandLine.allowOnly(Set.of("--cluster", "--description", "--labels", "--expiration",
        "--add-labels", "--remove-labels"));
    Tunnel reference = requireTunnelReference();
    commandLine.maxPositionals(0);
    Tunnel existing = getTunnelOrThrow(reference, options());
    Tunnel update = new Tunnel();
    update.tunnelId = existing.tunnelId;
    update.clusterId = existing.clusterId;
    update.name = existing.name;
    update.domain = existing.domain;
    update.description = commandLine.get("--description");
    if (commandLine.has("--labels") || commandLine.has("--add-labels")
        || commandLine.has("--remove-labels")) {
      Set<String> labels = new LinkedHashSet<>();
      if (commandLine.has("--labels")) {
        labels.addAll(commandLine.getAll("--labels"));
      } else if (existing.labels != null) {
        labels.addAll(Arrays.asList(existing.labels));
      }
      labels.addAll(commandLine.getAll("--add-labels"));
      labels.removeAll(commandLine.getAll("--remove-labels"));
      update.labels = labels.toArray(new String[0]);
    }
    update.customExpiration = commandLine.has("--expiration")
        ? parseDurationSeconds(commandLine.get("--expiration")) : existing.customExpiration;
    Tunnel updated = managementClient.updateTunnelAsync(update, options()).join();
    if (commandLine.flag("--json")) {
      out.println(json.toJson(updated));
      return EXIT_OK;
    }
    out.println("Updated tunnel: " + formatTunnelId(updated));
    printTunnel(updated);
    return EXIT_OK;
  }

  private int deleteTunnel() {
    commandLine.allowOnly(Set.of("--cluster"));
    Tunnel reference = requireTunnelReference();
    commandLine.maxPositionals(0);
    boolean deleted = managementClient.deleteTunnelAsync(reference, options()).join();
    out.println(deleted ? "Deleted tunnel: " + formatTunnelId(reference)
        : "Tunnel not found: " + formatTunnelId(reference));
    return deleted ? EXIT_OK : EXIT_ERROR;
  }

  // ---------------------------------------------------------------------------------------
  // Port commands

  private int portCommand() {
    String subcommand = commandLine.shift();
    if (subcommand == null) {
      throw new UsageException("Specify a port command: list, show, create, update or delete.");
    }
    switch (subcommand) {
      case "list": {
        commandLine.allowOnly(Set.of("--cluster"));
        Tunnel reference = requireTunnelReference();
        commandLine.maxPositionals(0);
        Collection<TunnelPort> ports =
            managementClient.listTunnelPortsAsync(reference, options()).join();
        if (commandLine.flag("--json")) {
          out.println(json.toJson(ports));
          return EXIT_OK;
        }
        if (ports == null || ports.isEmpty()) {
          out.println("No ports.");
          return EXIT_OK;
        }
        Table table = new Table("Port", "Protocol", "Description", "Forwarding URIs");
        for (TunnelPort port : ports) {
          table.add(String.valueOf(port.portNumber),
              port.protocol != null ? port.protocol : "auto",
              port.description != null ? port.description : "",
              port.portForwardingUris != null ? String.join(" ", port.portForwardingUris) : "");
        }
        table.print(out);
        return EXIT_OK;
      }
      case "show": {
        commandLine.allowOnly(Set.of("--cluster", "--port"));
        Tunnel reference = requireTunnelReference();
        int portNumber = requirePortNumber();
        TunnelRequestOptions options = options();
        options.includeAccessControl = true;
        TunnelPort port =
            managementClient.getTunnelPortAsync(reference, portNumber, options).join();
        if (port == null) {
          throw new IllegalStateException("Port not found: " + portNumber);
        }
        if (commandLine.flag("--json")) {
          out.println(json.toJson(port));
          return EXIT_OK;
        }
        printPort(port);
        return EXIT_OK;
      }
      case "create":
      case "add": {
        commandLine.allowOnly(Set.of("--cluster", "--port", "--protocol", "--description",
            "--labels", "--allow-anonymous"));
        Tunnel reference = requireTunnelReference();
        commandLine.maxPositionals(0);
        List<TunnelPort> ports = parsePorts();
        if (ports.isEmpty()) {
          throw new UsageException("Specify the port number with --port.");
        }
        for (TunnelPort port : ports) {
          applyPortOptions(port);
          TunnelPort created =
              managementClient.createTunnelPortAsync(reference, port, options()).join();
          out.println("Created port " + created.portNumber + " ("
              + (created.protocol != null ? created.protocol : "auto") + ").");
        }
        return EXIT_OK;
      }
      case "update": {
        commandLine.allowOnly(Set.of("--cluster", "--port", "--protocol", "--description",
            "--labels", "--allow-anonymous"));
        Tunnel reference = requireTunnelReference();
        TunnelPort port = new TunnelPort();
        port.portNumber = requirePortNumber();
        port.protocol = commandLine.get("--protocol");
        applyPortOptions(port);
        TunnelPort updated =
            managementClient.updateTunnelPortAsync(reference, port, options()).join();
        if (commandLine.flag("--json")) {
          out.println(json.toJson(updated));
          return EXIT_OK;
        }
        printPort(updated);
        return EXIT_OK;
      }
      case "delete":
      case "remove": {
        commandLine.allowOnly(Set.of("--cluster", "--port"));
        Tunnel reference = requireTunnelReference();
        int portNumber = requirePortNumber();
        boolean deleted =
            managementClient.deleteTunnelPortAsync(reference, portNumber, options()).join();
        out.println(deleted ? "Deleted port " + portNumber + "."
            : "Port not found: " + portNumber);
        return deleted ? EXIT_OK : EXIT_ERROR;
      }
      default:
        throw new UsageException("Unknown port command: " + subcommand);
    }
  }

  private void applyPortOptions(TunnelPort port) {
    if (commandLine.has("--description")) {
      port.description = commandLine.get("--description");
    }
    List<String> labels = commandLine.getAll("--labels");
    if (!labels.isEmpty()) {
      port.labels = labels.toArray(new String[0]);
    }
    if (commandLine.flag("--allow-anonymous")) {
      port.accessControl = new TunnelAccessControl();
      port.accessControl.entries = new TunnelAccessControlEntry[] {
          anonymousEntry(List.of(TunnelAccessScopes.connect))};
    }
  }

  private int requirePortNumber() {
    String value = commandLine.get("--port");
    if (value == null) {
      value = commandLine.shift();
    }
    commandLine.maxPositionals(0);
    if (value == null) {
      throw new UsageException("Specify the port number with --port.");
    }
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new UsageException("Invalid port number: " + value);
    }
  }

  private void printPort(TunnelPort port) {
    out.println("Port number           : " + port.portNumber);
    out.println("Protocol              : " + (port.protocol != null ? port.protocol : "auto"));
    if (port.description != null) {
      out.println("Description           : " + port.description);
    }
    if (port.labels != null && port.labels.length > 0) {
      out.println("Labels                : " + String.join(", ", port.labels));
    }
    printAccessControl(port.accessControl, "Access control        : ");
    if (port.portForwardingUris != null) {
      for (String uri : port.portForwardingUris) {
        out.println("Forwarding URI        : " + uri);
      }
    }
    if (port.inspectionUri != null) {
      out.println("Inspection URI        : " + port.inspectionUri);
    }
  }

  // ---------------------------------------------------------------------------------------
  // Access commands

  private int accessCommand() {
    String subcommand = commandLine.shift();
    if (subcommand == null) {
      throw new UsageException("Specify an access command: list, create or reset.");
    }
    switch (subcommand) {
      case "list":
      case "show": {
        commandLine.allowOnly(Set.of("--cluster", "--port"));
        Tunnel reference = requireTunnelReference();
        commandLine.maxPositionals(0);
        TunnelRequestOptions options = options();
        options.includeAccessControl = true;
        TunnelAccessControl accessControl;
        Integer portNumber = commandLine.getInt("--port");
        if (portNumber != null) {
          TunnelPort port =
              managementClient.getTunnelPortAsync(reference, portNumber, options).join();
          if (port == null) {
            throw new IllegalStateException("Port not found: " + portNumber);
          }
          accessControl = port.accessControl;
        } else {
          accessControl = getTunnelOrThrow(reference, options).accessControl;
        }
        if (commandLine.flag("--json")) {
          out.println(json.toJson(accessControl));
          return EXIT_OK;
        }
        printAccessControl(accessControl, "Access control entries:");
        return EXIT_OK;
      }
      case "create": {
        commandLine.allowOnly(Set.of("--cluster", "--port", "--anonymous", "--allow-anonymous",
            "--scopes", "--deny"));
        Tunnel reference = requireTunnelReference();
        commandLine.maxPositionals(0);
        if (!commandLine.flag("--anonymous") && !commandLine.flag("--allow-anonymous")) {
          throw new UsageException(
              "Only anonymous access entries are supported; specify --anonymous.");
        }
        List<String> scopes = commandLine.getAll("--scopes");
        if (scopes.isEmpty()) {
          scopes = List.of(TunnelAccessScopes.connect);
        }
        TunnelAccessControlEntry entry = anonymousEntry(scopes);
        entry.isDeny = commandLine.has("--deny");
        return modifyAccessControl(reference, entries -> {
          entries.add(entry);
          return entries;
        });
      }
      case "reset": {
        commandLine.allowOnly(Set.of("--cluster", "--port"));
        Tunnel reference = requireTunnelReference();
        commandLine.maxPositionals(0);
        return modifyAccessControl(reference, entries -> new ArrayList<>());
      }
      default:
        throw new UsageException("Unknown access command: " + subcommand);
    }
  }

  private int modifyAccessControl(
      Tunnel reference,
      java.util.function.UnaryOperator<List<TunnelAccessControlEntry>> change) {
    TunnelRequestOptions options = options();
    options.includeAccessControl = true;
    Integer portNumber = commandLine.getInt("--port");
    TunnelAccessControl result;
    if (portNumber != null) {
      TunnelPort port =
          managementClient.getTunnelPortAsync(reference, portNumber, options).join();
      if (port == null) {
        throw new IllegalStateException("Port not found: " + portNumber);
      }
      port.accessControl = applyChange(port.accessControl, change);
      result = managementClient.updateTunnelPortAsync(reference, port, options()).join()
          .accessControl;
    } else {
      Tunnel tunnel = getTunnelOrThrow(reference, options);
      Tunnel update = new Tunnel();
      update.tunnelId = tunnel.tunnelId;
      update.clusterId = tunnel.clusterId;
      update.name = tunnel.name;
      update.domain = tunnel.domain;
      update.customExpiration = tunnel.customExpiration;
      update.accessControl = applyChange(tunnel.accessControl, change);
      TunnelRequestOptions updateOptions = options();
      updateOptions.includeAccessControl = true;
      result = managementClient.updateTunnelAsync(update, updateOptions).join().accessControl;
    }
    if (commandLine.flag("--json")) {
      out.println(json.toJson(result));
    } else {
      printAccessControl(result, "Access control entries:");
    }
    return EXIT_OK;
  }

  private static TunnelAccessControl applyChange(
      TunnelAccessControl accessControl,
      java.util.function.UnaryOperator<List<TunnelAccessControlEntry>> change) {
    List<TunnelAccessControlEntry> entries = new ArrayList<>();
    if (accessControl != null && accessControl.entries != null) {
      for (TunnelAccessControlEntry entry : accessControl.entries) {
        if (!entry.isInherited) {
          entries.add(entry);
        }
      }
    }
    TunnelAccessControl updated = new TunnelAccessControl();
    updated.entries = change.apply(entries).toArray(new TunnelAccessControlEntry[0]);
    return updated;
  }

  // ---------------------------------------------------------------------------------------
  // Token command

  private int getToken() {
    commandLine.allowOnly(Set.of("--cluster", "--scopes"));
    Tunnel reference = requireTunnelReference();
    commandLine.maxPositionals(0);
    List<String> scopes = commandLine.getAll("--scopes");
    if (scopes.isEmpty()) {
      scopes = List.of(TunnelAccessScopes.connect);
    }
    TunnelRequestOptions options = options();
    options.tokenScopes = scopes;
    Tunnel tunnel = getTunnelOrThrow(reference, options);
    if (tunnel.accessTokens == null || tunnel.accessTokens.isEmpty()) {
      throw new IllegalStateException("The service did not issue any access tokens.");
    }
    if (commandLine.flag("--json")) {
      out.println(json.toJson(tunnel.accessTokens));
      return EXIT_OK;
    }
    out.println("Tunnel ID : " + formatTunnelId(tunnel));
    for (Map.Entry<String, String> token : tunnel.accessTokens.entrySet()) {
      out.println("Scope     : " + token.getKey());
      out.println("Token     : " + token.getValue());
    }
    return EXIT_OK;
  }

  // ---------------------------------------------------------------------------------------
  // Host and connect

  private int host() throws InterruptedException {
    commandLine.allowOnly(Set.of("--cluster", "--port", "--protocol", "--allow-anonymous",
        "--keep", "--no-reconnect", "--local-host", "--description", "--expiration"));
    String referenceText = commandLine.shift();
    commandLine.maxPositionals(0);
    List<TunnelPort> requestedPorts = parsePorts();

    Tunnel reference;
    boolean temporary = false;
    if (referenceText == null) {
      if (requestedPorts.isEmpty()) {
        throw new UsageException(
            "Specify a tunnel to host, or one or more --port values to host a temporary tunnel.");
      }
      Tunnel newTunnel = new Tunnel();
      newTunnel.clusterId = commandLine.get("--cluster");
      newTunnel.description = commandLine.get("--description");
      newTunnel.ports = requestedPorts.toArray(new TunnelPort[0]);
      if (commandLine.has("--expiration")) {
        newTunnel.customExpiration = parseDurationSeconds(commandLine.get("--expiration"));
      }
      if (commandLine.flag("--allow-anonymous")) {
        newTunnel.accessControl = new TunnelAccessControl();
        newTunnel.accessControl.entries = new TunnelAccessControlEntry[] {
            anonymousEntry(List.of(TunnelAccessScopes.connect))};
      }
      reference = managementClient.createTunnelAsync(newTunnel, options()).join();
      temporary = !commandLine.flag("--keep");
      out.println("Created " + (temporary ? "temporary " : "") + "tunnel: "
          + formatTunnelId(reference));
    } else {
      reference = parseTunnelReference(referenceText, commandLine.get("--cluster"));
      for (TunnelPort port : requestedPorts) {
        managementClient.createOrUpdateTunnelPortAsync(reference, port, options()).join();
      }
      if (commandLine.flag("--allow-anonymous")) {
        modifyAccessControlQuietly(reference);
      }
    }

    TunnelRequestOptions options = options();
    options.tokenScopes = List.of(TunnelAccessScopes.host, TunnelAccessScopes.connect);
    options.includePorts = true;
    Tunnel tunnel;
    String accessToken = auth.getTunnelAccessToken();
    try {
      tunnel = getTunnelOrThrow(reference, options);
    } catch (CompletionException e) {
      if (accessToken == null) {
        throw e;
      }
      // A host access token may not be allowed to request tokens; use it directly.
      TunnelRequestOptions plain = options();
      plain.includePorts = true;
      tunnel = getTunnelOrThrow(reference, plain);
    }
    if (accessToken != null) {
      tunnel.accessTokens = tunnel.accessTokens != null
          ? new java.util.HashMap<>(tunnel.accessTokens) : new java.util.HashMap<>();
      tunnel.accessTokens.putIfAbsent(TunnelAccessScopes.host, accessToken);
    }
    if (tunnel.ports == null || tunnel.ports.length == 0) {
      err.println("Warning: the tunnel has no ports. Add ports with 'port create' "
          + "(the host picks them up automatically when clients refresh ports).");
    }

    TunnelRelayTunnelHost host = new TunnelRelayTunnelHost(managementClient,
        new TunnelHostListener() {
          @Override
          public void onConnected(String protocol) {
            err.println("Host connected to the relay (" + protocol + ").");
          }

          @Override
          public void onDisconnected(String reason, boolean reconnecting) {
            err.println(reason + (reconnecting ? " Reconnecting..." : ""));
          }

          @Override
          public void onForwardedConnection(int port, String originator) {
            if (commandLine.flag("--verbose")) {
              err.println("Connection to port " + port + " from " + originator);
            }
          }

          @Override
          public void onClientSessionChanged(boolean connected) {
            err.println(connected ? "Client connected." : "Client disconnected.");
          }
        });
    host.setReconnectEnabled(!commandLine.flag("--no-reconnect"));
    host.setLocalHost(commandLine.get("--local-host"));

    CountDownLatch stopped = new CountDownLatch(1);
    final Tunnel hostedTunnel = tunnel;
    final boolean deleteOnExit = temporary;
    Thread shutdownHook = new Thread(() -> {
      err.println("Stopping host...");
      host.stop();
      if (deleteOnExit) {
        try {
          managementClient.deleteTunnelAsync(hostedTunnel, options()).join();
          err.println("Deleted temporary tunnel " + formatTunnelId(hostedTunnel) + ".");
        } catch (RuntimeException e) {
          err.println("Failed to delete temporary tunnel: " + describeError(e));
        }
      }
      stopped.countDown();
    }, "devtunnel-shutdown");
    Runtime.getRuntime().addShutdownHook(shutdownHook);

    try {
      host.connectAsync(tunnel).join();
    } catch (RuntimeException e) {
      Runtime.getRuntime().removeShutdownHook(shutdownHook);
      host.stop();
      if (deleteOnExit) {
        managementClient.deleteTunnelAsync(tunnel, options()).join();
      }
      throw e;
    }

    out.println();
    out.println("Hosting tunnel: " + formatTunnelId(tunnel));
    if (tunnel.ports != null) {
      for (TunnelPort port : tunnel.ports) {
        List<String> uris = getPortUris(tunnel, port);
        out.println("Port " + port.portNumber + (port.protocol != null
            ? " (" + port.protocol + ")" : "") + (uris.isEmpty() ? "" : ": " + uris.get(0)));
        for (int i = 1; i < uris.size(); i++) {
          out.println("      " + uris.get(i));
        }
        if (port.inspectionUri != null) {
          out.println("      Inspect: " + port.inspectionUri);
        }
      }
    }
    String connectToken = tunnel.accessTokens.get(TunnelAccessScopes.connect);
    if (connectToken != null && commandLine.flag("--verbose")) {
      out.println("Client connect token: " + connectToken);
    }
    out.println();
    out.println("Ready to accept connections. Press Ctrl+C to stop.");
    stopped.await();
    return EXIT_OK;
  }

  private void modifyAccessControlQuietly(Tunnel reference) {
    TunnelRequestOptions options = options();
    options.includeAccessControl = true;
    Tunnel tunnel = getTunnelOrThrow(reference, options);
    boolean hasAnonymous = tunnel.accessControl != null && tunnel.accessControl.entries != null
        && Arrays.stream(tunnel.accessControl.entries).anyMatch(e ->
            e.type == TunnelAccessControlEntryType.Anonymous && !e.isDeny);
    if (hasAnonymous) {
      return;
    }
    Tunnel update = new Tunnel();
    update.tunnelId = tunnel.tunnelId;
    update.clusterId = tunnel.clusterId;
    update.name = tunnel.name;
    update.domain = tunnel.domain;
    update.customExpiration = tunnel.customExpiration;
    update.accessControl = applyChange(tunnel.accessControl, entries -> {
      entries.add(anonymousEntry(List.of(TunnelAccessScopes.connect)));
      return entries;
    });
    managementClient.updateTunnelAsync(update, options()).join();
  }

  private int connect() throws InterruptedException {
    commandLine.allowOnly(Set.of("--cluster", "--host-id"));
    Tunnel reference = requireTunnelReference();
    commandLine.maxPositionals(0);
    TunnelRequestOptions options = options();
    options.tokenScopes = List.of(TunnelAccessScopes.connect);
    options.includePorts = true;
    Tunnel tunnel = getTunnelOrThrow(reference, options);
    String accessToken = auth.getTunnelAccessToken();
    if (accessToken != null) {
      tunnel.accessTokens = tunnel.accessTokens != null
          ? new java.util.HashMap<>(tunnel.accessTokens) : new java.util.HashMap<>();
      tunnel.accessTokens.putIfAbsent(TunnelAccessScopes.connect, accessToken);
    }
    if (tunnel.accessTokens == null
        || tunnel.accessTokens.get(TunnelAccessScopes.connect) == null) {
      throw new IllegalStateException("Could not get a connect access token for the tunnel.");
    }

    TunnelRelayTunnelClient client = new TunnelRelayTunnelClient();
    client.getForwardedPorts().addListener(new ForwardedPortEventListener() {
      @Override
      public void onForwardedPortAdded(ForwardedPort port) {
        out.println("Forwarding from 127.0.0.1:" + port.getLocalPort()
            + " to host port " + port.getRemotePort() + ".");
      }

      @Override
      public void onForwardedPortRemoved(ForwardedPort port) {
        out.println("Stopped forwarding port " + port.getRemotePort() + ".");
      }
    });

    CountDownLatch stopped = new CountDownLatch(1);
    Runtime.getRuntime().addShutdownHook(new Thread(() -> {
      err.println("Disconnecting...");
      try {
        client.stop();
      } catch (RuntimeException e) {
        // Not connected.
      }
      stopped.countDown();
    }, "devtunnel-shutdown"));

    client.connectAsync(tunnel, commandLine.get("--host-id")).join();
    out.println("Connected to tunnel: " + formatTunnelId(tunnel));
    out.println("Press Ctrl+C to disconnect.");
    stopped.await();
    return EXIT_OK;
  }

  // ---------------------------------------------------------------------------------------
  // Service info commands

  private int listClusters() {
    commandLine.allowOnly(Set.of("--recommend", "--geo", "--cluster"));
    commandLine.maxPositionals(0);
    if (commandLine.flag("--recommend")) {
      ClusterRecommendationResponse response = managementClient.getClusterRecommendationsAsync(
          commandLine.get("--cluster"), commandLine.get("--geo")).join();
      if (commandLine.flag("--json")) {
        out.println(json.toJson(response));
        return EXIT_OK;
      }
      out.println("Recommended cluster: " + response.recommendedClusterId
          + (response.isFallback ? " (fallback)" : ""));
      if (response.recommendations != null) {
        Table table = new Table("Cluster", "Location", "Geo", "Availability", "Reason");
        for (ClusterRecommendation recommendation : response.recommendations) {
          table.add(recommendation.clusterId, recommendation.azureLocation,
              recommendation.azureGeo, String.valueOf(recommendation.availability),
              recommendation.reason != null ? recommendation.reason : "");
        }
        table.print(out);
      }
      return EXIT_OK;
    }
    Collection<ClusterDetails> clusters = managementClient.listClustersAsync().join();
    if (commandLine.flag("--json")) {
      out.println(json.toJson(clusters));
      return EXIT_OK;
    }
    Table table = new Table("Cluster", "Location", "URI");
    for (ClusterDetails cluster : clusters) {
      table.add(cluster.clusterId, cluster.azureLocation, cluster.uri);
    }
    table.print(out);
    return EXIT_OK;
  }

  private int listLimits() {
    commandLine.allowOnly(Set.of());
    commandLine.maxPositionals(0);
    Collection<NamedRateStatus> limits = managementClient.listUserLimitsAsync().join();
    if (commandLine.flag("--json")) {
      out.println(json.toJson(limits));
      return EXIT_OK;
    }
    Table table = new Table("Limit", "Current", "Maximum");
    for (NamedRateStatus limit : limits) {
      table.add(limit.name, String.valueOf(limit.current), String.valueOf(limit.limit));
    }
    table.print(out);
    return EXIT_OK;
  }

  private int checkName() {
    commandLine.allowOnly(Set.of());
    String name = commandLine.shift();
    commandLine.maxPositionals(0);
    if (name == null) {
      throw new UsageException("A tunnel name is required.");
    }
    boolean available = managementClient.checkNameAvailabilityAsync(name).join();
    out.println(available ? "The name '" + name + "' is available."
        : "The name '" + name + "' is not available.");
    return available ? EXIT_OK : EXIT_ERROR;
  }

  // ---------------------------------------------------------------------------------------
  // Helpers

  /** Produces a readable message for an error, including service problem details. */
  static String describeError(Throwable error) {
    Throwable cause = error;
    while ((cause instanceof CompletionException || cause instanceof ExecutionException)
        && cause.getCause() != null) {
      cause = cause.getCause();
    }
    if (cause instanceof HttpResponseException) {
      HttpResponseException http = (HttpResponseException) cause;
      String detail = describeProblem(http.responseBody);
      String hint = "";
      if (http.statusCode == 401) {
        hint = " Run 'user login' to sign in, or pass an access token.";
      } else if (http.statusCode == 403) {
        hint = " You do not have access to this resource.";
      } else if (http.statusCode == 404) {
        hint = " The tunnel or port was not found.";
      }
      return "The tunnel service returned HTTP " + http.statusCode
          + (detail != null ? ": " + detail : ".") + hint;
    }
    String message = cause.getMessage();
    return message != null ? message : cause.toString();
  }

  private static String describeProblem(String body) {
    if (body == null || body.isBlank()) {
      return null;
    }
    try {
      ProblemDetails problem = new Gson().fromJson(body, ProblemDetails.class);
      if (problem != null && (problem.title != null || problem.detail != null)) {
        StringBuilder text = new StringBuilder();
        if (problem.title != null) {
          text.append(problem.title);
        }
        if (problem.detail != null) {
          text.append(text.length() > 0 ? " " : "").append(problem.detail);
        }
        if (problem.errors != null) {
          problem.errors.forEach((field, messages) ->
              text.append(" ").append(field).append(": ").append(String.join(" ", messages)));
        }
        return text.toString();
      }
      JsonObject object = new Gson().fromJson(body, JsonObject.class);
      return object != null ? object.toString() : body;
    } catch (RuntimeException e) {
      return body.length() > 300 ? body.substring(0, 300) + "..." : body;
    }
  }

  private static void configureLogging(boolean verbose) {
    System.setProperty("java.util.logging.SimpleFormatter.format",
        "%1$tT %4$s %3$s: %5$s%6$s%n");
    LogManager.getLogManager().reset();
    Logger root = Logger.getLogger("");
    ConsoleHandler handler = new ConsoleHandler();
    handler.setLevel(Level.ALL);
    root.addHandler(handler);
    root.setLevel(verbose ? Level.INFO : Level.WARNING);
    Logger.getLogger("com.microsoft.tunnels").setLevel(verbose ? Level.FINE : Level.WARNING);
    // Failed requests are reported by the CLI itself.
    Logger.getLogger("com.microsoft.tunnels.management")
        .setLevel(verbose ? Level.FINE : Level.SEVERE);
    // MINA and Netty are noisy at WARNING (e.g. unverified host keys); only show errors.
    Logger.getLogger("org.apache.sshd").setLevel(verbose ? Level.INFO : Level.SEVERE);
    Logger.getLogger("io.netty").setLevel(verbose ? Level.INFO : Level.SEVERE);
  }

  private void printHelp() {
    out.println("DeVibeTunnel " + VERSION + " - command-line client for Microsoft dev tunnels");
    out.println();
    out.println("Usage: java -jar devibetunnel.jar <command> [arguments] [options]");
    out.println();
    out.println("User commands:");
    out.println("  user login                Sign in with GitHub using a device code");
    out.println("  user logout               Remove saved credentials");
    out.println("  user show                 Show how requests are authenticated");
    out.println();
    out.println("Tunnel commands (TUNNEL is <tunnelId>.<clusterId> as shown by list, or a name):");
    out.println("  list                      List your tunnels [--labels a,b] [--all-labels]");
    out.println("                              [--cluster ID] [--limit N]");
    out.println("  show TUNNEL               Show tunnel details");
    out.println("  create [TUNNEL_ID]        Create a tunnel [-p PORT[:PROTOCOL]]... [-a]");
    out.println("                              [--description TEXT] [--labels a,b]");
    out.println("                              [--expiration 30d] [--cluster ID] [--geo GEO]");
    out.println("  update TUNNEL             Update [--description] [--labels | --add-labels |");
    out.println("                              --remove-labels a,b] [--expiration 30d]");
    out.println("  delete TUNNEL             Delete a tunnel");
    out.println("  token TUNNEL              Issue access tokens [--scopes connect,host,...]");
    out.println();
    out.println("Port commands:");
    out.println("  port list TUNNEL");
    out.println("  port show TUNNEL -p PORT");
    out.println("  port create TUNNEL -p PORT [--protocol http|https|tcp|ssh|auto]");
    out.println("                              [--description TEXT] [-a]");
    out.println("  port update TUNNEL -p PORT [--protocol P] [--description TEXT]");
    out.println("  port delete TUNNEL -p PORT");
    out.println();
    out.println("Access commands:");
    out.println("  access list TUNNEL [-p PORT]");
    out.println("  access create TUNNEL --anonymous [--scopes connect] [--deny] [-p PORT]");
    out.println("  access reset TUNNEL [-p PORT]");
    out.println();
    out.println("Connections:");
    out.println("  host [TUNNEL]             Host a tunnel, forwarding connections to local");
    out.println("                              ports.");
    out.println("                              Without TUNNEL, creates a temporary tunnel for the");
    out.println("                              given -p ports (deleted on exit unless --keep).");
    out.println("                              [-p PORT[:PROTOCOL]]... [-a] [--no-reconnect]");
    out.println("                              [--local-host HOST]");
    out.println("  connect TUNNEL            Connect as a client and forward the tunnel ports");
    out.println("                              to local ports [--host-id ID]");
    out.println();
    out.println("Service:");
    out.println("  clusters                  List clusters [--recommend [--geo GEO]]");
    out.println("  limits                    Show your usage limits");
    out.println("  check-name NAME           Check whether a tunnel name is available");
    out.println();
    out.println("Global options:");
    out.println("  --github-token TOKEN      Authenticate with a GitHub token");
    out.println("  --aad-token TOKEN         Authenticate with a Microsoft Entra ID token");
    out.println("  --user-token VALUE        Full Authorization header value, e.g. \"github X\"");
    out.println("  -t, --access-token TOKEN  Use a tunnel access token");
    out.println("  -e, --env ENV             Service environment: prod (default), ppe, dev,");
    out.println("                              local");
    out.println("  --service-uri URI         Override the tunnel service URI");
    out.println("  -j, --json                Print JSON output");
    out.println("  -v, --verbose             Verbose logging");
    out.println("  --version                 Print the version");
    out.println();
    out.println("Environment variables: DEVIBETUNNEL_GITHUB_TOKEN, DEVIBETUNNEL_AAD_TOKEN,");
    out.println("  DEVIBETUNNEL_USER_TOKEN, DEVIBETUNNEL_ACCESS_TOKEN, DEVIBETUNNEL_ENV,");
    out.println("  DEVIBETUNNEL_HOME (credential directory), DEVTUNNELS_PROTOCOL_VERSION.");
  }

  /** Formats rows as aligned text columns. */
  private static final class Table {
    private final String[] headers;
    private final List<String[]> rows = new ArrayList<>();

    Table(String... headers) {
      this.headers = headers;
    }

    void add(String... values) {
      String[] row = new String[headers.length];
      for (int i = 0; i < headers.length; i++) {
        row[i] = i < values.length && values[i] != null ? values[i] : "";
      }
      rows.add(row);
    }

    void print(PrintStream out) {
      int[] widths = new int[headers.length];
      for (int i = 0; i < headers.length; i++) {
        widths[i] = headers[i].length();
        for (String[] row : rows) {
          widths[i] = Math.max(widths[i], row[i].length());
        }
      }
      printRow(out, headers, widths);
      for (String[] row : rows) {
        printRow(out, row, widths);
      }
    }

    private static void printRow(PrintStream out, String[] values, int[] widths) {
      StringBuilder line = new StringBuilder();
      for (int i = 0; i < values.length; i++) {
        line.append(values[i]);
        if (i < values.length - 1) {
          line.append(" ".repeat(widths[i] - values[i].length() + 2));
        }
      }
      out.println(line.toString().stripTrailing());
    }
  }
}

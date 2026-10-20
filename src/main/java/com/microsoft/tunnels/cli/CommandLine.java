// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.cli;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * A small command-line parser: positional arguments plus {@code --name value},
 * {@code --name=value}, short aliases ({@code -p 8080}) and boolean flags. Options may appear
 * anywhere; {@code --} ends option parsing.
 */
final class CommandLine {
  /** Thrown for invalid usage; the CLI prints the message and exits with code 2. */
  static final class UsageException extends RuntimeException {
    UsageException(String message) {
      super(message);
    }
  }

  private static final Map<String, String> ALIASES = Map.ofEntries(
      Map.entry("-p", "--port"),
      Map.entry("-v", "--verbose"),
      Map.entry("-h", "--help"),
      Map.entry("-a", "--allow-anonymous"),
      Map.entry("-d", "--description"),
      Map.entry("-l", "--labels"),
      Map.entry("-g", "--github"),
      Map.entry("-f", "--force"),
      Map.entry("-e", "--env"),
      Map.entry("-t", "--access-token"),
      Map.entry("-c", "--cluster"),
      Map.entry("-j", "--json"));

  /** Options that take no value. */
  static final Set<String> FLAGS = Set.of(
      "--verbose", "--help", "--allow-anonymous", "--github", "--device-code", "--force",
      "--json", "--all-labels", "--recommend", "--version", "--no-reconnect", "--anonymous",
      "--keep", "--deny");

  private final List<String> positionals;
  private final Map<String, List<String>> options;

  private CommandLine(List<String> positionals, Map<String, List<String>> options) {
    this.positionals = positionals;
    this.options = options;
  }

  static CommandLine parse(String[] args) {
    List<String> positionals = new ArrayList<>();
    Map<String, List<String>> options = new LinkedHashMap<>();
    boolean optionsEnded = false;
    for (int i = 0; i < args.length; i++) {
      String arg = args[i];
      if (optionsEnded || !arg.startsWith("-") || arg.equals("-")) {
        positionals.add(arg);
        continue;
      }
      if (arg.equals("--")) {
        optionsEnded = true;
        continue;
      }
      String name = arg;
      String value = null;
      int equals = arg.indexOf('=');
      if (arg.startsWith("--") && equals > 0) {
        name = arg.substring(0, equals);
        value = arg.substring(equals + 1);
      }
      name = ALIASES.getOrDefault(name, name);
      if (!name.startsWith("--")) {
        throw new UsageException("Unknown option: " + arg);
      }
      if (FLAGS.contains(name)) {
        if (value != null) {
          throw new UsageException("Option " + name + " does not take a value.");
        }
        value = "true";
      } else if (value == null) {
        if (i + 1 >= args.length) {
          throw new UsageException("Option " + name + " requires a value.");
        }
        value = args[++i];
      }
      options.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
    }
    return new CommandLine(positionals, options);
  }

  List<String> positionals() {
    return Collections.unmodifiableList(positionals);
  }

  /** Removes and returns the first positional argument, or null if there is none. */
  String shift() {
    return positionals.isEmpty() ? null : positionals.remove(0);
  }

  boolean has(String name) {
    return options.containsKey(name);
  }

  boolean flag(String name) {
    return options.containsKey(name);
  }

  /** The last value of an option, or null. */
  String get(String name) {
    List<String> values = options.get(name);
    return values == null ? null : values.get(values.size() - 1);
  }

  String get(String name, String defaultValue) {
    String value = get(name);
    return value != null ? value : defaultValue;
  }

  /** All values of a repeatable option; comma-separated values are split. */
  List<String> getAll(String name) {
    List<String> result = new ArrayList<>();
    for (String value : options.getOrDefault(name, List.of())) {
      for (String part : value.split(",")) {
        if (!part.isBlank()) {
          result.add(part.trim());
        }
      }
    }
    return result;
  }

  Integer getInt(String name) {
    String value = get(name);
    if (value == null) {
      return null;
    }
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException e) {
      throw new UsageException("Option " + name + " must be a number: " + value);
    }
  }

  /**
   * Fails if any option other than the allowed (or global) ones was given.
   */
  void allowOnly(Set<String> allowed) {
    for (String name : options.keySet()) {
      if (!allowed.contains(name) && !DeVibeTunnelCli.GLOBAL_OPTIONS.contains(name)) {
        throw new UsageException("Unknown option for this command: " + name);
      }
    }
  }

  /** Fails if more positional arguments remain than allowed. */
  void maxPositionals(int count) {
    if (positionals.size() > count) {
      throw new UsageException("Unexpected argument: " + positionals.get(count));
    }
  }
}

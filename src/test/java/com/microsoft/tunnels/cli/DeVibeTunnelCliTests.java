// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.cli;

import com.microsoft.tunnels.cli.CommandLine.UsageException;
import com.microsoft.tunnels.contracts.Tunnel;
import com.microsoft.tunnels.management.HttpResponseException;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletionException;

import org.junit.Assert;
import org.junit.Test;

/**
 * Tests CLI argument handling that does not need the tunnel service.
 */
public class DeVibeTunnelCliTests {
  @Test
  public void parsesOptionsAliasesAndFlags() {
    CommandLine commandLine = CommandLine.parse(new String[] {
        "host", "-p", "8080", "--port=3000:https", "-a", "--description", "my app", "extra"});
    Assert.assertEquals("host", commandLine.shift());
    Assert.assertEquals(List.of("8080", "3000:https"), commandLine.getAll("--port"));
    Assert.assertTrue(commandLine.flag("--allow-anonymous"));
    Assert.assertEquals("my app", commandLine.get("--description"));
    Assert.assertEquals(List.of("extra"), commandLine.positionals());
  }

  @Test
  public void splitsCommaSeparatedValues() {
    CommandLine commandLine = CommandLine.parse(new String[] {"--labels", "a, b", "-l", "c"});
    Assert.assertEquals(List.of("a", "b", "c"), commandLine.getAll("--labels"));
  }

  @Test(expected = UsageException.class)
  public void missingOptionValueIsAnError() {
    CommandLine.parse(new String[] {"list", "--cluster"});
  }

  @Test(expected = UsageException.class)
  public void flagWithValueIsAnError() {
    CommandLine.parse(new String[] {"--json=yes"});
  }

  @Test
  public void parsesTunnelReferences() {
    Tunnel byId = DeVibeTunnelCli.parseTunnelReference("happy-lake-abc123.usw2", null);
    Assert.assertEquals("happy-lake-abc123", byId.tunnelId);
    Assert.assertEquals("usw2", byId.clusterId);
    Assert.assertNull(byId.name);

    Tunnel byName = DeVibeTunnelCli.parseTunnelReference("my-tunnel", null);
    Assert.assertEquals("my-tunnel", byName.name);
    Assert.assertNull(byName.tunnelId);

    Tunnel withCluster = DeVibeTunnelCli.parseTunnelReference("abc123", "euw");
    Assert.assertEquals("abc123", withCluster.tunnelId);
    Assert.assertEquals("euw", withCluster.clusterId);

    Assert.assertEquals("happy-lake-abc123.usw2", DeVibeTunnelCli.formatTunnelId(byId));
  }

  @Test
  public void parsesDurations() {
    Assert.assertEquals(30 * 86400, DeVibeTunnelCli.parseDurationSeconds("30d"));
    Assert.assertEquals(2 * 3600, DeVibeTunnelCli.parseDurationSeconds("2h"));
    Assert.assertEquals(90 * 60, DeVibeTunnelCli.parseDurationSeconds("90m"));
    Assert.assertEquals(45, DeVibeTunnelCli.parseDurationSeconds("45s"));
    Assert.assertEquals(3600, DeVibeTunnelCli.parseDurationSeconds("3600"));
  }

  @Test(expected = UsageException.class)
  public void invalidDurationIsAnError() {
    DeVibeTunnelCli.parseDurationSeconds("10w");
  }

  @Test
  public void describesServiceErrors() {
    HttpResponseException http = new HttpResponseException("failed", 403,
        "{\"title\":\"Forbidden\",\"detail\":\"Not allowed.\"}");
    String message = DeVibeTunnelCli.describeError(new CompletionException(http));
    Assert.assertTrue(message, message.contains("HTTP 403"));
    Assert.assertTrue(message, message.contains("Forbidden Not allowed."));
  }

  @Test
  public void reportsUsageErrorsWithExitCode2() {
    ByteArrayOutputStream errors = new ByteArrayOutputStream();
    PrintStream err = new PrintStream(errors, true, StandardCharsets.UTF_8);
    PrintStream out = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
    int exitCode = new DeVibeTunnelCli(out, err).run(new String[] {"no-such-command"});
    Assert.assertEquals(2, exitCode);
    Assert.assertTrue(errors.toString(StandardCharsets.UTF_8).contains("Unknown command"));
  }

  @Test
  public void printsHelp() {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8);
    Assert.assertEquals(0, new DeVibeTunnelCli(out, out).run(new String[] {"--help"}));
    String help = output.toString(StandardCharsets.UTF_8);
    Assert.assertTrue(help.contains("user login"));
    Assert.assertTrue(help.contains("host [TUNNEL]"));
  }
}

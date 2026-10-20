## DeVibeTunnel

DeVibeTunnel is a Java client, host and command-line interface (CLI) for the
[Microsoft dev tunnels](https://aka.ms/devtunnels/docs) service. It manages tunnels through the
tunnel service API, hosts tunnels (forwarding incoming connections to local ports) and connects
to tunnels as a client. The build produces a single standalone, runnable jar.

> **Vibe coded with Claude.** This project was vibe coded: the code, tests and documentation
> were written by Claude (Anthropic's AI model, via Claude Code), directed and tested by a
> human, rather than written by hand. It is based on the open-source
> [dev tunnels Java SDK](https://github.com/microsoft/dev-tunnels/tree/main/java) by Microsoft
> (MIT license), which Claude extended with the CLI, tunnel hosting, GitHub device code
> sign-in and a number of fixes. Review it accordingly before relying on it.

DeVibeTunnel is an independent project. It is not made, endorsed or supported by Microsoft;
"dev tunnels" refers to the Microsoft service it connects to.

- [Requirements](#requirements)
- [Building](#building)
- [Running the CLI](#running-the-cli)
- [Quick start](#quick-start)
- [Signing in](#signing-in)
- [Command reference](#command-reference)
- [Environment variables and files](#environment-variables-and-files)
- [Troubleshooting](#troubleshooting)
- [Using the SDK as a library](#using-the-sdk-as-a-library)
- [Updating the contract classes](#updating-the-contract-classes)
- [Limitations](#limitations)
- [License](#license)

### Requirements
- **To run the CLI:** a Java runtime, version 11 or later. Nothing else is needed; the jar
  contains all of its dependencies.
- **To build:** JDK 11 or later and [Maven](https://maven.apache.org/install.html) 3.6 or later.
- Network access to the tunnel service (`*.rel.tunnels.api.visualstudio.com`, `*.devtunnels.ms`)
  and, for signing in, to `github.com`.

### Building
From the directory that contains `pom.xml`:
```
mvn package
```
To skip the tests, add `-DskipTests`. (`TunnelManagementClientTests` and `TunnelClientTests`
run against the live service and fail unless `TEST_TUNNEL_TOKEN` and `TEST_TUNNEL_NAME` are set.)

The build produces one jar, `target/devibetunnel.jar`: the standalone,
runnable CLI with all dependencies included. Copy it anywhere and run it with `java -jar`.

(The plain SDK jar that the CLI jar is built from is kept in `target/intermediate/`. It is
also what `mvn install` installs as the library artifact.)

### Running the CLI
```
java -jar devibetunnel.jar <command> [arguments] [options]
java -jar devibetunnel.jar --help
java -jar devibetunnel.jar --version
```
Tip: define an alias, for example in `~/.bashrc`:
```
alias devibetunnel='java -jar /path/to/devibetunnel.jar'
```
The examples below use `devibetunnel` for brevity.

#### Identifying tunnels
Commands that take a `TUNNEL` argument accept the tunnel ID in the form
`<tunnelId>.<clusterId>`, exactly as `list` prints it (for example `happy-lake-abc1234.usw2`).
You can also pass the tunnel ID with `--cluster <clusterId>`, or a tunnel name.

### Quick start
```
# 1. Sign in with GitHub (device code; see "Signing in").
devibetunnel user login

# 2. Share a local web app on port 8080 through a temporary tunnel that anyone can open.
#    The public URL is printed; the tunnel is deleted when you press Ctrl+C (add --keep to keep it).
devibetunnel host -p 8080 --allow-anonymous
```

#### A persistent tunnel
```
devibetunnel create my-tunnel -p 3000:https --expiration 30d
devibetunnel list                         # shows the tunnel ID, e.g. my-tunnel.usw2
devibetunnel host my-tunnel.usw2          # run on the machine with the service on port 3000
```

#### SSH through a tunnel
On the machine that runs the SSH server (port 22 in this example):
```
devibetunnel create my-ssh -p 22
devibetunnel host my-ssh.usw2
```
On the client machine, signed in with an account that has access to the tunnel:
```
devibetunnel connect my-ssh.usw2
# Prints e.g. "Forwarding from 127.0.0.1:22 to host port 22." If the port is already in use
# locally, another free port is used instead (e.g. 23) - use the port that is printed:
ssh -p 22 user@127.0.0.1
```
`connect` verifies the tunnel host's identity: the host must prove it holds the private key
for the public key it published on the tunnel endpoint, otherwise the connection is refused.
The SSH server's own host key is then checked by `ssh` as usual (compare its fingerprint with
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server the first time you connect).

Press Ctrl+C to stop `host` or `connect`. `host` removes its endpoint from the tunnel when it
stops.

### Signing in
Most commands need you to be signed in. There are several ways; the first one found is used:

| Method | How |
|---|---|
| Option on the command | `--user-token VALUE` (a complete `Authorization` header value, e.g. `"github gho_..."`), `--github-token TOKEN`, or `--aad-token TOKEN` (Microsoft Entra ID) |
| Environment variable | `DEVIBETUNNEL_USER_TOKEN`, `DEVIBETUNNEL_GITHUB_TOKEN`, or `DEVIBETUNNEL_AAD_TOKEN` |
| Saved login | `devibetunnel user login` (GitHub device code) |

**GitHub device code login.** `user login` prints a short code and the URL
https://github.com/login/device. Open the URL in a browser on any device, enter the code and
approve access; the CLI waits until you do (the code expires after 15 minutes):
```
$ devibetunnel user login
To sign in with GitHub, open https://github.com/login/device in a browser and enter the code:

    ABCD-1234

Waiting for authorization (the code expires in 14 minutes)...
Logged in as octocat using GitHub.
```
The credentials are saved in `~/.devibetunnel/credentials.json`, which only your user can
read. They are stored per service environment (see `--env`). `user show` shows which
credentials are used (and when the token expires); `user logout` deletes them.

**Tunnel access tokens.** For operations on a single tunnel you can use a tunnel access token
instead of signing in, with `--access-token TOKEN` (`-t`) or `DEVIBETUNNEL_ACCESS_TOKEN`. Someone
with access to the tunnel can issue one with `devibetunnel token TUNNEL --scopes connect`
(or `host`, `manage`, ...). For example, to connect without signing in:
```
devibetunnel connect my-tunnel.usw2 --access-token <connect token>
```

### Command reference
Run any command with `--help` to see the overview. Options can appear anywhere on the command
line; options that take a list accept comma-separated values or can be repeated.

#### User
| Command | Description |
|---|---|
| `user login [--scopes S]` | Sign in with GitHub using a device code. |
| `user show` | Show how requests are authenticated. |
| `user logout` | Delete the saved credentials. |

`login` and `logout` also work without the `user` prefix.

#### Tunnels
| Command | Options | Description |
|---|---|---|
| `list` | `--labels a,b` `--all-labels` `--cluster ID` `--limit N` | List your tunnels (optionally only those with the given labels; with `--all-labels`, only those with all of them). |
| `show TUNNEL` | | Show details: status, access control, ports and their URLs. |
| `create [TUNNEL_ID]` | `-p PORT[:PROTOCOL]`... `-a/--allow-anonymous` `-d/--description TEXT` `-l/--labels a,b` `--expiration 30d` `--cluster ID` `--geo GEO` `--name NAME` | Create a tunnel. Without an ID, one is generated; without `--cluster`, the recommended cluster is used. |
| `update TUNNEL` | `--description TEXT` `--labels a,b` \| `--add-labels a,b` `--remove-labels a,b` `--expiration 30d` | Update a tunnel. |
| `delete TUNNEL` | | Delete a tunnel. |
| `token TUNNEL` | `--scopes connect,host,...` | Issue tunnel access tokens (default scope: `connect`). |

Durations are written as a number and a unit: `d` (days), `h`, `m` or `s`, e.g. `7d` or `12h`.

#### Ports
| Command | Options | Description |
|---|---|---|
| `port list TUNNEL` | | List the ports of a tunnel. |
| `port show TUNNEL -p PORT` | | Show a port, including its forwarding and inspection URLs. |
| `port create TUNNEL -p PORT` | `--protocol P` `--description TEXT` `--labels a,b` `-a` | Add a port. `-p` can be repeated, or written as `PORT:PROTOCOL`. |
| `port update TUNNEL -p PORT` | `--protocol P` `--description TEXT` `--labels a,b` `-a` | Update a port. |
| `port delete TUNNEL -p PORT` | | Remove a port. |

Protocols: `auto` (default), `http`, `https`, `tcp`, `ssh`, `rdp`. A running host picks up port
changes when a client refreshes ports (the `connect` command does not need to be restarted).

#### Access control
| Command | Options | Description |
|---|---|---|
| `access list TUNNEL` | `-p PORT` | List access control entries of the tunnel (or of a port). |
| `access create TUNNEL --anonymous` | `--scopes connect` `--deny` `-p PORT` | Allow (or with `--deny`, deny) anonymous access. |
| `access reset TUNNEL` | `-p PORT` | Remove all access control entries that are not inherited. |

Without an anonymous entry, only you (and accounts you grant access to) can connect; the
browser URLs require signing in.

#### Connections
| Command | Options | Description |
|---|---|---|
| `host [TUNNEL]` | `-p PORT[:PROTOCOL]`... `-a/--allow-anonymous` `--keep` `--no-reconnect` `--local-host HOST` `--description TEXT` `--expiration 30d` `--cluster ID` | Host a tunnel: accept connections from clients and browsers and forward them to local ports. With `TUNNEL`, any `-p` ports are added to it. Without `TUNNEL`, a temporary tunnel is created for the `-p` ports and deleted on exit (unless `--keep`). |
| `connect TUNNEL` | `--host-id ID` | Connect as a client and forward every tunnel port to a local port on 127.0.0.1 (the same number if free, otherwise another free port, which is printed). |

`host` forwards connections to `127.0.0.1` (falling back to `::1`); use `--local-host` to
forward to another address. It reconnects automatically if the relay connection drops (unless
`--no-reconnect`), renewing the host access token when needed. Only one host can be connected
to a tunnel at a time; if another host connects, the first one stops.

#### Service
| Command | Options | Description |
|---|---|---|
| `clusters` | `--recommend` `--geo GEO` `--cluster ID` | List the service clusters, or with `--recommend`, the recommended clusters for new tunnels. |
| `limits` | | Show your usage limits. |
| `check-name NAME` | | Check whether a tunnel name is available. |

#### Global options
| Option | Description |
|---|---|
| `-j, --json` | Print the result as JSON (for `list`, `show`, `create`, `update`, `token`, `port`, `access`, `clusters`, `limits`). |
| `-v, --verbose` | Verbose logging to stderr (HTTP requests, relay connection details). |
| `-e, --env ENV` | Service environment: `prod` (default), `ppe`, `dev` or `local`. |
| `--service-uri URI` | Override the tunnel service URI. |
| `-t, --access-token TOKEN` | Use a tunnel access token. |
| `--github-token`, `--aad-token`, `--user-token` | User credentials; see [Signing in](#signing-in). |
| `-h, --help` | Show help. |
| `--version` | Show the version. |

#### Exit codes
| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | The operation failed (for example a service error, the tunnel or port was not found, or `check-name` found the name taken). |
| `2` | Invalid command line. |

### Environment variables and files
| Name | Description |
|---|---|
| `DEVIBETUNNEL_GITHUB_TOKEN` | GitHub token used to authenticate. |
| `DEVIBETUNNEL_AAD_TOKEN` | Microsoft Entra ID token used to authenticate. |
| `DEVIBETUNNEL_USER_TOKEN` | Complete `Authorization` header value used to authenticate. |
| `DEVIBETUNNEL_ACCESS_TOKEN` | Tunnel access token. |
| `DEVIBETUNNEL_ENV` | Default service environment (same values as `--env`). |
| `DEVIBETUNNEL_HOME` | Directory for saved credentials (default `~/.devibetunnel`). |
| `DEVTUNNELS_PROTOCOL_VERSION` | Force the host relay protocol: `1` or `2` (default: both offered, the relay chooses). |
| `~/.devibetunnel/credentials.json` | Saved login (owner-only permissions). Delete it, or run `user logout`, to sign out. |

### Troubleshooting
| Symptom | What to do |
|---|---|
| `HTTP 401` | You are not signed in, or the token expired: run `user login` (or check the token you passed). |
| `HTTP 403` | Your account has no access to that tunnel or operation. |
| `HTTP 404` | Check the tunnel ID including the cluster (`list` shows the full ID). |
| `connect` reports no hosts accepting connections | Start `host` for the tunnel first; `show` displays the host connection count. |
| A browser shows 502 for the tunnel URL | The host is running but nothing listens on that local port. |
| `Host public key verification failed` | The host's identity did not match the key on the tunnel endpoint. Re-run `connect` (the host may have restarted); if it persists, do not trust the connection. |
| Anything else | Re-run with `--verbose` for details and a stack trace. |

### Using the SDK as a library
Use the SDK jar (installed to your local Maven repository by `mvn install` as
`com.microsoft.tunnels:devibetunnel`, or `target/intermediate/devibetunnel-<version>.jar`)
and its dependencies (see `pom.xml`), or simply put the CLI jar on the classpath. Main classes (in `com.microsoft.tunnels`):

| Class | Purpose |
|---|---|
| `management.TunnelManagementClient` | Tunnel service API: tunnels, ports, endpoints, clusters, limits. |
| `connections.TunnelRelayTunnelHost` | Host a tunnel and forward connections to local ports. |
| `connections.TunnelRelayTunnelClient` | Connect to a tunnel and forward its ports locally. |
| `auth.GitHubDeviceCodeAuthenticator` | GitHub device code sign-in. |
| `auth.CredentialStore` | Saved credentials, as used by the CLI. |

Example: sign in with a GitHub device code and host an existing tunnel.
```java
var properties = TunnelServiceProperties.production;
var auth = new GitHubDeviceCodeAuthenticator(properties.gitHubAppClientId);
var code = auth.requestDeviceCode(GitHubDeviceCodeAuthenticator.DEFAULT_SCOPES);
System.out.println("Open " + code.verificationUri + " and enter " + code.userCode);
String token = auth.pollForToken(code, null).accessToken;

var management = new TunnelManagementClient(
    new ProductHeaderValue[] {new ProductHeaderValue("my-app", "1.0")},
    () -> CompletableFuture.completedFuture("github " + token),
    TunnelManagementClient.ApiVersions[0]);

Tunnel tunnel = new Tunnel();
tunnel.tunnelId = "my-tunnel";
tunnel.clusterId = "usw2";

TunnelRelayTunnelHost host = new TunnelRelayTunnelHost(management);
host.connectAsync(tunnel).join();   // forwards the tunnel's ports to 127.0.0.1
// ...
host.stop();                        // disconnects and removes the host endpoint
```

### Updating the contract classes
The classes in `src/main/java/com/microsoft/tunnels/contracts/` describe the tunnel service's
API objects (tunnels, ports, endpoints, access control and so on). They are **already included
as ordinary Java source**, so building DeVibeTunnel needs no C# tooling. You only need this
section to pick up changes to the service API, for example new properties.

The contract classes are not written by hand. Upstream, they are defined once in C#
(`cs/src/Contracts/*.cs` in [microsoft/dev-tunnels](https://github.com/microsoft/dev-tunnels))
and a code generator (`cs/tools/TunnelsSDK.Generator`) produces the Java, TypeScript, Go and
Rust versions. Each generated Java file starts with a `// Generated from ...` comment naming its
C# source. Five files in the package are hand-written and must not be replaced:
`TunnelContracts.java` (JSON serialization setup) and `TunnelAccessControlStatics.java`,
`TunnelConstraintsStatics.java`, `TunnelEndpointStatics.java` and
`TunnelServicePropertiesStatics.java` (logic that the generated classes call).

The generator runs as part of the C# build and writes into the `java/` folder of the checkout
it runs in, so the update is done in a dev-tunnels checkout and then copied here:

1. Get the dev-tunnels sources with the contract changes you want, either the latest upstream
   version or your own edits to `cs/src/Contracts/*.cs`:
   ```
   git clone https://github.com/microsoft/dev-tunnels.git
   ```
2. Install the [.NET SDK](https://dotnet.microsoft.com/download) version named in
   `cs/global.json` of the checkout (currently 10.0.201 or a later 10.0 feature release).
   Without administrator rights you can install it into a directory of your choice:
   ```
   curl -sSL https://dot.net/v1/dotnet-install.sh -o dotnet-install.sh
   bash dotnet-install.sh --jsonfile dev-tunnels/cs/global.json --install-dir ~/.dotnet
   export PATH="$HOME/.dotnet:$PATH"
   ```
3. Build the C# contracts project for `net8.0` (the target framework the generator is
   attached to). This regenerates the contract classes in `dev-tunnels/java/` (and the other
   languages):
   ```
   cd dev-tunnels/cs
   dotnet build src/Contracts/DevTunnels.Contracts.csproj -f net8.0
   ```
4. Copy the regenerated Java classes into this project. The script copies only generated
   files, never the hand-written ones, and lists contract classes that were added or that are
   no longer generated:
   ```
   scripts/update-contracts.sh /path/to/dev-tunnels
   ```
5. Review the changes with `git diff`, then build and test (`mvn package`). If a new contract
   class has a static member, the generated code calls a method in a matching
   `<Name>Statics.java` class; write that class by hand, modeled on the existing ones. If the
   service adds a new kind of tunnel endpoint, also register it in the endpoint deserializer
   in `TunnelContracts.java`.

The generated files use the package `com.microsoft.tunnels.contracts`; if you rename the Java
packages, the copied files need the same rename.

### Limitations
- End-to-end encryption of relay (V2 protocol) connections is not supported by the host;
  when a client requests it, the connection continues without it and is protected by the
  relay's TLS connection.
- Sign-in by device code is available for GitHub accounts. Microsoft Entra ID tokens can be
  used with `--aad-token` but cannot be obtained by the CLI itself.
- Expired GitHub logins are renewed automatically when GitHub issues a refresh token;
  otherwise run `user login` again.
- The client (`connect`) does not reconnect automatically after the connection drops.

### License
The SDK is licensed under the [MIT license](LICENSE). The standalone CLI jar also bundles
third-party libraries under the Apache License 2.0 (Apache MINA SSHD, Netty, Gson, Apache
Commons IO, Apache Maven Shared Utils, jcl-over-slf4j) and the MIT license (SLF4J). The jar
contains the license texts and notices: `META-INF/LICENSE.txt`,
`META-INF/THIRD-PARTY-NOTICES.txt`, `META-INF/licenses/` and `META-INF/NOTICE`. The source
copies are in `src/license/`.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package com.microsoft.tunnels.connections.ssh;

/**
 * SSH message numbers and reason codes (RFC 4250, 4253, 4254) used by the relay transport.
 */
public final class SshMessages {
  private SshMessages() {
  }

  public static final int DISCONNECT = 1;
  public static final int IGNORE = 2;
  public static final int UNIMPLEMENTED = 3;
  public static final int DEBUG = 4;
  public static final int SERVICE_REQUEST = 5;
  public static final int SERVICE_ACCEPT = 6;
  public static final int EXT_INFO = 7;
  public static final int KEXINIT = 20;
  public static final int NEWKEYS = 21;
  public static final int GLOBAL_REQUEST = 80;
  public static final int REQUEST_SUCCESS = 81;
  public static final int REQUEST_FAILURE = 82;
  public static final int CHANNEL_OPEN = 90;
  public static final int CHANNEL_OPEN_CONFIRMATION = 91;
  public static final int CHANNEL_OPEN_FAILURE = 92;
  public static final int CHANNEL_WINDOW_ADJUST = 93;
  public static final int CHANNEL_DATA = 94;
  public static final int CHANNEL_EXTENDED_DATA = 95;
  public static final int CHANNEL_EOF = 96;
  public static final int CHANNEL_CLOSE = 97;
  public static final int CHANNEL_REQUEST = 98;
  public static final int CHANNEL_SUCCESS = 99;
  public static final int CHANNEL_FAILURE = 100;

  public static final int DISCONNECT_PROTOCOL_ERROR = 2;
  public static final int DISCONNECT_KEY_EXCHANGE_FAILED = 3;
  public static final int DISCONNECT_CONNECTION_LOST = 10;
  public static final int DISCONNECT_BY_APPLICATION = 11;
  public static final int DISCONNECT_TOO_MANY_CONNECTIONS = 12;

  public static final int OPEN_ADMINISTRATIVELY_PROHIBITED = 1;
  public static final int OPEN_CONNECT_FAILED = 2;
  public static final int OPEN_UNKNOWN_CHANNEL_TYPE = 3;
  public static final int OPEN_RESOURCE_SHORTAGE = 4;
}

# Trollback
Interception tool for the Throwback command and control software

```
C2 Server Options:
  Options to communicate with C2 server

  -t TARGET_URI, --target TARGET_URI
                        URL of the C2 server to target.
  -k CRYPTO_KEY, --crypto-key CRYPTO_KEY
                        RC4 crypto key used by the server.
  -a POSTAUTH_KEY, --post-auth POSTAUTH_KEY
                        POST authentification key for requests to the server.
  -cc COMMAND_CODE, --command-code COMMAND_CODE
                        Command code used by server.
  -rk RESPONSE_KEY, --response-key RESPONSE_KEY
                        Response key to use when reply to a command.
  -sk STRINGS_KEY, --strings-key STRINGS_KEY
                        XOR key used to unobfuscate strings in implant.

Flooding Options:
  Options to flood the C2 with random data

  -d ACTION_FLOOD, --decoys ACTION_FLOOD
                        Nb. of fake hosts to authentify with the C2 server
  -b, --beacon          Sends a beacon to the specified C2 server.
  -s ACTION_SCAN, --scan ACTION_SCAN
                        File or directory to scan for Throwback implant.
  -f ACTION_SEARCH [ACTION_SEARCH ...], --find ACTION_SEARCH [ACTION_SEARCH ...]
                        Searches for files containing keywords in given
                        directory.
  -i, --indicators      Extract indicators from scanned files.

```

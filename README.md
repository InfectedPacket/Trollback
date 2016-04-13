# Trollback
Interception tool for the Throwback command and control software

```
C2 Server Options:
  Options to communicate with C2 server

  -t url, --target url  URL of the C2 server to target.
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

Operations:
  Operations/Counter-Ops available.

  -d nb_hosts, --decoys nb_hosts
                        Nb. of fake hosts to authentify with the C2 server
  -b milliseconds, --beacon milliseconds
                        Sends a beacon to the specified C2 server.
  -s file | directory, --scan file | directory
                        File or directory to scan for Throwback implant.
  -f file | directory [file | directory ...], --find file | directory [file | directory ...]
                        Searches for files containing keywords in given
                        directory.
  -i, --indicators      Extract indicators from scanned files.
  -p, --probe           Probe Throwback C2 servers for information.
  -l EVENT_LOG, --log EVENT_LOG
                        Specifies a file to keep a log of events.
  --noexec              Prevents execution of files uploaded by adversary.

File I/O Options:
  File management options

  -dd DOWN_DIR, --download DOWN_DIR
                        Destination directory for downloaded file
  -bd BACK_DIR, --backup BACK_DIR
                        Backup directory for files downloaded.
  -vv, --verbose        Shows lots of strings and characters...

Host:
  Information about the target host.

  -hn Hostname, --hostname Hostname
                        Name of the host.
  -id Machine ID, --guid Machine ID
                        Guid of the host.
  -ip IPv4 Address      IPv4 address of the local machine.

Connection Options:
  Options to connect

  -pp host:port, --proxy host:port
                        Proxy to send the requests, if any.

```

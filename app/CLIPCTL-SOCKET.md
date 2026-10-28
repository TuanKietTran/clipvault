# clipctl Unix-socket protocol

The `clipctl` executable connects to `$CLIPVAULT_SOCKET`, or by default `~/Library/Application Support/ClipVault/clipvault.sock`. The socket is a local Unix stream socket. Each request and response is one UTF-8 JSON object terminated by LF. The service must validate references independently and must never place payloads in responses, diagnostics, or logs.

Requests:

```json
{"command":"list","reference":null}
{"command":"copy","reference":"clip://<UUID>"}
{"command":"paste","reference":"clip://<UUID>"}
```

Responses:

```json
{"ok":true,"items":[{"reference":"clip://<UUID>","type":"text","size":12,"sourceApp":"Example","timestamp":"2026-01-01T00:00:00Z","sensitivityLabel":"normal","providerTag":"local-encrypted"}]}
{"ok":true}
{"ok":false,"error":"opaque, secret-free error"}
```

`list` returns each item's opaque `clip://UUID` reference alongside metadata (type, size, source app, timestamp, sensitivity label, provider tag). It must never include item content. `copy` resolves the opaque ref directly to the system pasteboard; `paste` performs the same resolution and synthesizes Cmd-V in the user session. Both are successful only after the service operation and neither response may contain the resolved value. Credential import is not a socket command. The socket service is hosted by the GUI application and enforces local-user access.

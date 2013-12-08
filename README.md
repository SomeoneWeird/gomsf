gomsf
======
... I choose you!

gomsf is a go library for interacting with Metasploits msgpack-RPC API.

gomsf exposes methods for all RPC endpoints for the open source edition of Metasploit.

Functions are written using camelCase instead of snake_case like in the MSF API documentation, thus

> session.meterpreter_run_single

becomes

> sessionMeterpreterRunSingle

which has the signature of

> session.meterpreter_run_single( String: SessionID, String: Command )

(from the MSFAPI documentation)
 
... which means you can run it like....

> rpcObject.sessionMeterpreterRunSingle(0, "getuid")

and then you could call sessionMeterpreterRead and read the output.

gomsf also exposes a Call function which you can use to direcly communicate with the connected rpc server.

> func (r *RPC) Call(args ...interface{})

**Most of the API calls that don't have any tests HAVE NOT been tested, you have been warned.*

LICENSE
---
See LICENSE file.
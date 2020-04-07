/*https://tools.ietf.org/html/rfc6455*/
module websock;
import std.socket;
import core.time;

enum WSS
{
	OPENING,
	OPENED,
	CLOSING,
	CLOSED
}
enum OPC
{
	CONTINUATION = 0x0,
	TEXT = 0x1,
	BINARY = 0x02,
	CLOSE = 0x8,
	PING = 0x9,
	PONG = 0xa
}
const uint HEARTBEAT = 300000;
struct Websock
{
	WSS state;
	Socket s;
	bool wait;
	bool fragmented;
	Duration heartbeat;
	ubyte[] buffer;
	ubyte[] msg;
	ubyte[] queued;
	void *user;
	void delegate (Websock *, ubyte[]) on_message;
	WS_server *owner;
}

void
websock_send (Websock *ws, OPC opcode, void[] data)
{
	import std.stdint;
	union C
	{
		uint64_t i;
		ubyte[8] b;
	}
	const uint LIMIT = 1300 - 4;
	const ubyte SMALL = 126;
	ubyte[] tmp = cast (ubyte[])data;
	ubyte[] msg;
	ubyte h;
	C c;
	/*Fragment gigantic messages. NB: LIMIT must be larger than SMALL bytes in
	order to ensure that control frames are never fragmented, as per the RFC
	mandate*/
	while (tmp.length >= LIMIT)
	{
		h = cast (ubyte)opcode;
		c.i = LIMIT;
		msg = [h] ~ [SMALL] ~ c.b[0 .. 2] ~ tmp[0 .. LIMIT];
		tmp = tmp[LIMIT .. $];
		ws.queued ~= msg;
	}
	/*Put together the final fragment, which may also be the only fragment*/
	h = 0x80|cast (ubyte)opcode;
	c.i = tmp.length;
	if (tmp.length < SMALL) msg = [h] ~ [c.b[0]];
	else msg = [h] ~ [SMALL] ~ [c.b[1], c.b[0]];
	msg ~= tmp[0 .. $];
	/*Control frames get prepended to the send queue, else prepended*/
	if (opcode >= OPC.PING)
	{
		if (126 <= tmp.length)
		{
			throw new Error ("Control frame data must be less than 126 bytes");
		}
		ws.queued = msg ~ ws.queued;
	}
	else ws.queued ~= msg;
}
private int
negotiate (Websock *ws)
{
	import std.stdio;
	import std.conv;
	import std.string;	
	/*RFC explicitly says we should avoid initial empty lines*/
	size_t index = 0;
	size_t i = 2;
	while (i < ws.buffer.length)
	{
		if (ws.buffer[i - 2] != '\r' && ws.buffer[i - 1] != '\n') 
		{
			break;
		}
		i++;
	}
	/*Chop buffer into lines*/
	string[] lines;
	string[string] headers;
	for (; i <= ws.buffer.length; i++)
	{
		if (ws.buffer[i - 2] != '\r' && ws.buffer[i - 1] != '\n') 
		{/*Scan for line break*/
			continue;
		}
		if (i - index <= 2)
		{/*An empty line denotes the end of the headers*/
			goto Headers;
		}
		lines ~= to!string (assumeUTF (ws.buffer[index .. i - 2])).strip ();
		index = i;
	}
	/*Wait for more data*/
	writeln ("waiting for more data...");
	writeln (lines);
	return 0;
Headers:	
	/*Ensure the first line is a GET request*/
	if (lines[0] != "GET / HTTP/1.1")
	{
		//throw new Error (
		//	format!"Expected GET request, but got %s"(lines[0])
		//);
		return -1;
	}
	/*Parse the buffer as much as we can*/
	foreach (line; lines[1 .. $])
	{
		/*End of headers marker*/
		if ("" == line)
		{
			break;
		}
		/*Parse out a key/value and stuff it into the table*/
		auto del = line.indexOf (":");
		if (del < 0)
		{
			//throw new Error (format!"Malformed pair (%s)"(line));
			return -1;
		}
		headers[toLower (line[0 .. del])] = strip (line[del + 1 .. $]);
	}
	/*Sanity check headers*/
	if ("sec-websocket-version" !in headers ||
		"sec-websocket-key" !in headers ||
		"connection" !in headers ||
		"upgrade" !in headers ||
		"host" !in headers)
	{
		//throw new Error ("Missing headers");
		return -1;
	}	
	/*MUST be set to websocket, as per RFC*/
	if (headers["upgrade"] != "websocket")
	{
		//throw new Error ("Invalid value for upgrade token");
		return -1;
	}
	/*Connection MUST contain an upgrade value*/
	auto tokens = headers["connection"].toLower ().split (",");
	foreach (token; tokens)
	{
		if (token.strip () != "upgrade") continue;
		goto Okay;
	}
	throw new Error ("missing upgrade value from connection");
Okay:
	/*Version MUST be 13 as per RFC*/
	if (headers["sec-websocket-version"] != "13")
	{
		//throw new Error ("Unsupported version");
		return -1;
	}
	/*Value MUST be 16 bytes long*/
	import std.base64;
	if (Base64.decode (headers["sec-websocket-key"]).length != 16)
	{
		//throw new Error ("Invalid key length");
		return -1;
	}
	/*Craft response*/
	import std.digest.sha;
	auto hash = sha1Of (
		headers["sec-websocket-key"] ~ "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
	);
	auto result = Base64.encode (hash);	
	auto resp = "HTTP/1.1 101 Switching Protocols\r\n";
	resp ~= "Upgrade: websocket\r\n";
	resp ~= "Connection: Upgrade\r\n";
	resp ~= "Sec-WebSocket-Accept: " ~ result ~ "\r\n";
	resp ~= "\r\n";
	/*Ensure the whole response goes out.
	Kind of a hack. would be better off buffered on the websock imo*/
	while (resp.length != 0)
	{
		auto sent = ws.s.send (resp);
		resp = resp[sent .. $];
	}
	/*Set websocket into open state*/
	ws.state = WSS.OPENED;
	ws.buffer.length = 0;
	if (ws.owner.cb.on_connect !is null)
	{
		ws.owner.cb.on_connect (ws.owner, ws);
	}
	return 0;
}
void
websock_read (Websock *ws)
{
	import std.stdint;
	{/*Read data off the socket and buffer it*/
		ubyte[4096] tmp;
		auto len = ws.s.receive (tmp[]);
		if (len <= 0)
		{
			ws.state = WSS.CLOSED;
			if (len < 0)
			{
				import std.stdio;
				writeln ("Socket error!");
				writeln (*ws);
			}
			return;
		}
		ws.buffer ~= tmp[0 .. len];
		ws.heartbeat = dur!"msecs" (HEARTBEAT);
	}
	/*Negotiate connection if still in opening state*/
	if (WSS.OPENING == ws.state)
	{
		if (negotiate (ws))
		{/*Something went wrong during negotiations*/
			ws.state = WSS.CLOSED;
		}
		return;
	}
	/*Try to parse buffered data*/
	ubyte[] data = ws.buffer;
	if (data.length < 2)
	{
		return;
	}
	uint64_t size = (data[1]&0x7f);
	ubyte[4] key;
	uint ofs;	
	/*Extract the size data*/
	if (126 == size)
	{
		if (data.length < 6)
		{
			return;
		}
		size = (data[2]<<8)|data[3];
		ofs = 4;
	}
	else if (127 == size)
	{
		if (data.length < 10)
		{
			return;
		}
		if ((data[2]&0x80) != 0)
		{
			throw new Error ("MSB for 64 bit size is not 0");
		}
		uint64_t hi = (data[2]<<24)|(data[3]<<16)|(data[4]<<8)|data[5];
		uint64_t lo = (data[6]<<24)|(data[7]<<16)|(data[8]<<8)|data[9];
		size = (hi<<32)|lo;
		ofs = 8;
	}
	else
	{
		ofs = 2;
	}
	/*Now extract the key, if the mask bit is set*/
	bool mask = (data[1]&0x80) != 0;
	if (mask)
	{
		if (data.length < ofs + 4)
		{
			return;
		}
		key = data[ofs .. ofs + 4];
		ofs += 4;
	}
	/*Ensure the whole fragment is here before trying to parse it*/
	if (data.length < ofs + size)
	{
		return;
	}
	bool fin = (data[0]&0x80) != 0;
	uint opc = (data[0]&0xf);
	switch (opc)
	{
	case OPC.TEXT: goto case;
	case OPC.BINARY:
		if (ws.fragmented)
		{
			throw new Error ("Bad opcode in the middle of fragment stream");
		}
		goto case;
	case OPC.CONTINUATION:
		/*Append fragment to the message body. If the mask bit is set then 
		the data has to be decoded first, else a raw copy works just fine*/
		if (mask)
		{
			for (auto i = 0; i < size; i++)
			{
				data[ofs + i] ^= key[i&3];
			}
		}
		/*Figure out where to source the message data. if ws.wait is set to
		true then all fragments are buffered before use, else the fragment is
		used once it arrives. This is permissible behaviour per the RFC.*/
		if (ws.wait)
		{
			ws.msg ~= data[ofs .. ofs + cast (uint)size];
			if (fin)
			{
				ws.on_message (ws, ws.msg);
				ws.fragmented = false;
				ws.msg.length = 0;
			}
			else ws.fragmented = true;
		}
		else
		{
			ws.on_message (ws, data[ofs .. cast (uint)size]);
			if (fin) ws.fragmented = false;
			else ws.fragmented = true;
			ws.msg.length = 0;
		}
		break;
	case OPC.CLOSE:
		ws.state = WSS.CLOSING;
		break;
	case OPC.PING:
		/*Ignore pings if closing*/
		if (WSS.CLOSING == ws.state)
		{
			break;
		}
		websock_send (ws, OPC.PONG, data[ofs .. ofs + cast (uint)size]);
		break;
	case OPC.PONG:
		/*Ignore if closing*/
		if (WSS.CLOSING == ws.state)
		{
			break;
		}
		break;
	default:
		throw new Error ("Unsupported websock opcode");
	}
	/*Remove the buffered data*/
	ws.buffer = ws.buffer[ofs + cast (uint)size .. $];
	/*Bump the heart beat*/
	ws.heartbeat = dur!"msecs" (HEARTBEAT);
}
void
websock_write (Websock *ws)
{
	if (0 == ws.queued.length)
	{
		return;
	}
	auto size = ws.s.send (ws.queued);
	if (Socket.ERROR != size)
	{
		ws.queued = ws.queued[size .. $];
	}
}
Websock *
websock_create (Socket sock)
{
	import core.stdc.string;
	Websock *ws = new Websock;
	memset (ws, 0, (*ws).sizeof);
	ws.state = WSS.OPENING;
	ws.heartbeat = dur!"msecs" (HEARTBEAT);
	ws.wait = true;
	ws.s = sock;
	ws.on_message = delegate (Websock *self, ubyte[] data) {};
	return ws;
}
void
websock_destroy (Websock *ws)
{	/*Shutdown the socket*/
	ws.s.shutdown (SocketShutdown.BOTH);
	ws.s.close ();
	ws.s = null;
	/*Release the buffers*/
	destroy (ws.buffer);
	destroy (ws.queued);
	destroy (ws.msg);
	/*Release the object*/
	destroy (ws);
}

struct WS_server_callbacks
{
	void function (WS_server *) on_open;
	void function (WS_server *) on_close;
	void function (WS_server *, Websock *) on_connect;
	void function (WS_server *, Websock *) on_disconnect;
}
struct WS_server
{
	WS_server_callbacks cb;
	Websock*[] socks;
	SocketSet read;
	SocketSet write;
	bool running;
}
void
ws_server_init (WS_server *sv, WS_server_callbacks *cb)
{
	sv.cb = *cb;
	sv.read = new SocketSet;
	sv.write = new SocketSet;
	sv.running = false;
}
void
ws_server_start (WS_server *sv, ushort port)
{
	import std.stdio;
	import std.conv;
	import std.string;
	/*Flag server as running*/
	sv.running = true;
	/*Create listen socket*/
	Socket spy = new Socket (
		AddressFamily.INET,
		SocketType.STREAM,
		ProtocolType.TCP
	);
	spy.bind (new InternetAddress (ADDR_ANY, port));
	spy.listen (100);
	/*Let the user do stuff now*/
	if (sv.cb.on_open)
	{
		sv.cb.on_open (sv);
	}
	/*Process data*/
	while (sv.running)
	{	/*Reset all of the socket sets... There has to be a better way?*/
		sv.read.reset ();
		sv.write.reset ();
		foreach (web; sv.socks)
		{
			sv.read.add (web.s);
			sv.write.add (web.s);
		}
		sv.read.add (spy);
		/*Wait for stuff to do*/
		Websock*[] tmp;
		auto before = MonoTime.currTime;
		auto num = Socket.select (sv.read, sv.write, null);
		if (num < 0)
		{
			continue;
		}
		auto after = MonoTime.currTime;
		auto tick = after - before;
		/*Admit one new connection*/
		if (sv.read.isSet (spy))
		{   /*Create a new websocket*/
			Socket sock = spy.accept ();
			auto ws = websock_create (sock);
			ws.owner = sv;
			tmp ~= ws;
		}
		/*Update the connections*/
		foreach (web; sv.socks)
		{	/*Remove old dead connections*/
			if (WSS.CLOSED == web.state || web.heartbeat <= dur!"msecs" (0))
			{
				if (sv.cb.on_disconnect !is null)
				{
					sv.cb.on_disconnect (sv, web);
				}
				websock_destroy (web);
				continue;
			}
			/*Drop heartbeat timer*/
			web.heartbeat -= tick;
			/*Send/receive data*/
			if (sv.write.isSet (web.s))
			{
				websock_write (web);
			}
			if (sv.read.isSet (web.s))
			{
				websock_read (web);
			}
			tmp ~= web;
		}
		/*Clear off dead sockets*/
		sv.socks = tmp;
	}
	/*Let the user do exit stuff now*/
	if (sv.cb.on_close)
	{
		sv.cb.on_close (sv);
	}
	spy.shutdown (SocketShutdown.BOTH);
	spy.close ();
}

unittest
{
	WS_server sv;
	WS_server_callbacks cb;
	cb.on_connect = function (WS_server *sv, Websock *ws)
	{
		/*Apply the message handler*/
		ws.on_message = delegate (Websock *self, ubyte[] data)
		{
			import std.stdio;
			import std.string;
			auto text = assumeUTF (data).strip ();
			writeln (text, " ", text.length);
			foreach (web; sv.socks)
			{
				if (web.state != WSS.OPENED)
				{
					continue;
				}
				websock_send (web, OPC.TEXT, text);
			}
		};
	};
	ws_server_init (&sv, &cb);
	ws_server_start (&sv, 8080);
}

#!/usr/bin/env python3
"""
bypass_proxy.py

A small but full-featured upstream proxy to sit in front of Burp (or other proxy)
and handle modern TLS/HTTP2 connections to origin servers. Accepts:
  - regular HTTP proxy requests (absolute-URI requests)
  - CONNECT requests (tunnels raw TCP between client and origin)

Usage:
  python bypass_proxy.py --help
  python bypass_proxy.py -p 8081 -b 127.0.0.1 -v

Features:
  - Asyncio based, concurrent
  - Uses httpx AsyncClient with http2=True for origin requests
  - Tunnels raw TCP for CONNECT
  - Simple allowlist option (--allow host[:port] multiple times)
  - Verbose logging
"""
import argparse
import asyncio
import logging
import signal
import sys
from urllib.parse import urlsplit

import httpx

# ---------- Configurable defaults ----------
DEFAULT_PORT = 8081
DEFAULT_BIND = "127.0.0.1"
READ_CHUNK = 65536
# -------------------------------------------

logger = logging.getLogger("bypass_proxy")


def parse_args():
    p = argparse.ArgumentParser(description="Upstream proxy that handles modern TLS/HTTP2 to origin")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT, help="Port to listen on (default: 8081)")
    p.add_argument("-b", "--bind", default=DEFAULT_BIND, help="Bind address (default: 127.0.0.1)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    p.add_argument("--allow", action="append", default=[], help="Allowlist host[:port] (can repeat). If empty, all hosts allowed.")
    return p.parse_args()


def setup_logging(verbose: bool):
    h = logging.StreamHandler()
    fmt = "%(asctime)s %(levelname)-5s %(message)s"
    h.setFormatter(logging.Formatter(fmt))
    logger.addHandler(h)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)


def host_allowed(host: str, allowlist):
    if not allowlist:
        return True
    for a in allowlist:
        if ":" in a:
            ah, ap = a.split(":", 1)
            if host == ah:
                return True
        else:
            if host == a:
                return True
    return False


async def handle_tunnel(local_reader: asyncio.StreamReader, local_writer: asyncio.StreamWriter, dest_host: str, dest_port: int):
    """
    For CONNECT: open a TCP socket to destination and relay bytes both ways.
    """
    logger.info("CONNECT tunnel: %s:%s", dest_host, dest_port)
    try:
        remote_reader, remote_writer = await asyncio.open_connection(dest_host, dest_port)
    except Exception as e:
        logger.error("Failed to connect to %s:%s -> %s", dest_host, dest_port, e)
        local_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await local_writer.drain()
        local_writer.close()
        return

    # inform client that tunnel is established
    local_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
    await local_writer.drain()

    async def pipe(reader, writer):
        try:
            while True:
                chunk = await reader.read(READ_CHUNK)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # Relay both directions
    await asyncio.gather(pipe(local_reader, remote_writer), pipe(remote_reader, local_writer))


async def handle_http_request(body_first_line: bytes, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, allowlist):
    """
    Handle non-CONNECT HTTP requests. The client sends absolute-form request lines when talking to a proxy.
    We'll parse the request, use httpx to fetch origin (with HTTP/2 support), then forward response back.
    """

    # read the rest of the HTTP headers and body (if any)
    request_data = bytearray()
    request_data.extend(body_first_line)
    # read until empty header line
    while True:
        line = await client_reader.readline()
        if not line:
            break
        request_data.extend(line)
        if line in (b"\r\n", b"\n", b""):
            break

    # parse method and URL from first line
    try:
        first_line = request_data.splitlines()[0].decode("utf-8", errors="replace").strip()
        method, full_url, http_ver = first_line.split(" ", 2)
    except Exception as e:
        logger.error("Failed to parse request first line: %s", e)
        client_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        return

    parsed = urlsplit(full_url)
    if not parsed.scheme:
        # some clients may send origin-form; build URL using Host header
        # simple attempt: find Host header
        headers = request_data.decode(errors="replace").splitlines()
        host = None
        for h in headers:
            if h.lower().startswith("host:"):
                host = h.split(":", 1)[1].strip()
                break
        if host:
            full_url = "https://" + host + full_url  # assume https if absent
            parsed = urlsplit(full_url)

    dest_host = parsed.hostname
    dest_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if not host_allowed(dest_host, allowlist):
        logger.warning("Host %s not allowed by allowlist", dest_host)
        client_writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
        await client_writer.drain()
        client_writer.close()
        return

    # read any body that may follow (content-length)
    # naive approach: look for Content-Length header and read that many bytes
    raw_headers = request_data.decode("utf-8", errors="replace")
    content_len = 0
    for line in raw_headers.splitlines():
        if line.lower().startswith("content-length:"):
            try:
                content_len = int(line.split(":", 1)[1].strip())
            except Exception:
                content_len = 0
            break

    body_bytes = b""
    if content_len > 0:
        body_bytes = await client_reader.readexactly(content_len)

    # Build headers for httpx
    hdr_lines = raw_headers.splitlines()[1:]  # skip request line
    headers = {}
    for line in hdr_lines:
        if not line or ":" not in line:
            continue
        k, v = line.split(":", 1)
        # remove hop-by-hop headers that shouldn't be forwarded
        if k.lower().strip() in ("proxy-connection", "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade"):
            continue
        headers[k.strip()] = v.strip()

    # Make request to origin using httpx (async client)
    # we disable ssl verification to avoid cert chain issues (like self-signed). change if you want verify=True.
    async with httpx.AsyncClient(http2=True, verify=False, timeout=30.0) as client:
        try:
            logger.debug("Forwarding %s %s -> %s:%s", method, full_url, dest_host, dest_port)
            resp = await client.request(method, full_url, headers=headers, content=body_bytes)
        except Exception as e:
            logger.error("Error fetching origin %s: %s", full_url, e)
            client_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_writer.drain()
            client_writer.close()
            return

    # Build response back to client
    status_line = f"HTTP/1.1 {resp.status_code} {resp.reason_phrase}\r\n"
    client_writer.write(status_line.encode("utf-8"))
    # copy response headers
    for k, v in resp.headers.items():
        # skip hop-by-hop headers
        if k.lower() in ("transfer-encoding", "connection", "keep-alive"):
            continue
        header_line = f"{k}: {v}\r\n"
        client_writer.write(header_line.encode("utf-8"))
    client_writer.write(b"\r\n")
    # write body
    client_writer.write(resp.content)
    await client_writer.drain()
    client_writer.close()
    logger.info("Relayed %s %s -> %s", method, full_url, resp.status_code)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, allowlist):
    peer = writer.get_extra_info("peername")
    logger.info("Client connected: %s", peer)
    try:
        # read first line to determine if CONNECT or normal request
        line = await reader.readline()
        if not line:
            writer.close()
            return
        first_line = line.decode("utf-8", errors="replace").strip()
        logger.debug("First line: %s", first_line)
        if first_line.upper().startswith("CONNECT"):
            # CONNECT host:port HTTP/1.1
            parts = first_line.split(" ")
            target = parts[1]
            if ":" in target:
                dest_host, dest_port_s = target.split(":", 1)
                try:
                    dest_port = int(dest_port_s)
                except Exception:
                    dest_port = 443
            else:
                dest_host = target
                dest_port = 443

            # consume remainder of headers
            while True:
                l = await reader.readline()
                if not l or l in (b"\r\n", b"\n"):
                    break

            if not host_allowed(dest_host, allowlist):
                logger.warning("CONNECT to %s blocked by allowlist", dest_host)
                writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            # Start tunneling
            await handle_tunnel(reader, writer, dest_host, dest_port)
        else:
            # Normal HTTP proxy request: first line already read (absolute-form)
            await handle_http_request(line, reader, writer, allowlist)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        logger.exception("Error handling client: %s", e)
        try:
            writer.close()
        except Exception:
            pass


async def run_server(bind_host: str, port: int, allowlist):
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, allowlist), bind_host, port)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    logger.info("Listening on %s (proxy). Allowlist: %s", addrs, allowlist or 'ALL')
    async with server:
        await server.serve_forever()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    # Basic startup checks
    try:
        import httpx  # ensure dependency
    except Exception:
        logger.error("Missing dependency 'httpx'. Install: pip install httpx")
        sys.exit(1)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, loop.stop)
        except Exception:
            pass

    try:
        loop.run_until_complete(run_server(args.bind, args.port, args.allow))
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        loop.close()


if __name__ == "__main__":
    main()

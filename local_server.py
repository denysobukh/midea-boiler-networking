#!/usr/bin/env python3
"""Record Midea TCP traffic while forwarding bytes unchanged to the real cloud."""
import argparse
import asyncio
import datetime
import json
from pathlib import Path
import ssl


class Frames:
    """Reassemble 8370 frames across arbitrary TCP read boundaries."""
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, chunk):
        self.buffer.extend(chunk)
        result = []
        while len(self.buffer) >= 6:
            if self.buffer[:2] != b'\x83\x70':
                self.buffer.clear()
                return result
            size = int.from_bytes(self.buffer[2:4], 'big') + 8
            if len(self.buffer) < size:
                break
            result.append(bytes(self.buffer[:size]))
            del self.buffer[:size]
        return result


async def serve(args):
    args.logs.mkdir(parents=True, exist_ok=True)
    events = (args.logs / 'events.jsonl').open('a', buffering=1)
    counter = 0
    active = 0
    connections = set()

    def log(event, **details):
        record = dict(time=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      event=event, **details)
        events.write(json.dumps(record) + '\n')
        if event != 'chunk':
            print(json.dumps(record), flush=True)

    async def proxy(reader, writer):
        nonlocal counter, active
        connection_task = asyncio.current_task()
        connections.add(connection_task)
        counter += 1
        active += 1
        session = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + f'-{counter}'
        upstream_writer = None
        log('connect', session=session, peer=writer.get_extra_info('peername'),
            upstream=[args.upstream, args.upstream_port])
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(
                asyncio.open_connection(args.upstream, args.upstream_port), 15)

            async def pump(source, destination, direction):
                parser = Frames()
                offset = 0
                with (args.logs / f'{session}-{direction}.bin').open('xb') as raw:
                    while True:
                        chunk = await source.read(65536)
                        if not chunk:
                            if destination.can_write_eof():
                                destination.write_eof()
                                await destination.drain()
                            log('eof', session=session, direction=direction, bytes=offset,
                                incomplete_frame_bytes=len(parser.buffer))
                            return
                        raw.write(chunk)
                        raw.flush()
                        log('chunk', session=session, direction=direction,
                            offset=offset, length=len(chunk))
                        offset += len(chunk)
                        destination.write(chunk)
                        await destination.drain()
                        for frame in parser.feed(chunk):
                            log('frame', session=session, direction=direction,
                                length=len(frame), type=frame[5] & 15,
                                header=frame[:6].hex(), hex=frame.hex())

            tasks = [asyncio.create_task(pump(reader, upstream_writer, 'device-to-cloud')),
                     asyncio.create_task(pump(upstream_reader, writer, 'cloud-to-device'))]
            try:
                await asyncio.gather(*tasks)
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as error:
            log('error', session=session, error=str(error))
        finally:
            for connection in (writer, upstream_writer):
                if connection is not None:
                    connection.close()
                    try:
                        await connection.wait_closed()
                    except (OSError, ssl.SSLError):
                        pass
            active -= 1
            log('closed', session=session)
            connections.discard(connection_task)

    async def status(reader, writer):
        try:
            request = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 10)
            first_line = request.split(b'\r\n', 1)[0].decode('ascii', errors='replace')
            log('status_request', peer=writer.get_extra_info('peername'), request=first_line)
            body = json.dumps(dict(service='Midea recording proxy', active_connections=active,
                                   total_connections=counter, upstream=args.upstream,
                                   upstream_port=args.upstream_port,
                                   proxy_port=args.proxy_port)).encode() + b'\n'
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n'
                         b'Connection: close\r\nContent-Length: ' + str(len(body)).encode()
                         + b'\r\n\r\n' + body)
            await writer.drain()
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError,
                asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    servers = []
    try:
        servers.append(await asyncio.start_server(proxy, args.bind, args.proxy_port))
        servers.append(await asyncio.start_server(status, args.bind, args.http_port))
        servers.append(await asyncio.start_server(status, args.bind, args.https_port,
                                                 ssl=context, ssl_handshake_timeout=10))
        log('listening', bind=args.bind, proxy_port=args.proxy_port,
            http_port=args.http_port, https_port=args.https_port)
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
        await asyncio.gather(*(server.wait_closed() for server in servers))
        for task in list(connections):
            task.cancel()
        await asyncio.gather(*list(connections), return_exceptions=True)
        events.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='192.168.200.164')
    parser.add_argument('--proxy-port', type=int, default=28443)
    parser.add_argument('--upstream', default='35.71.136.152')
    parser.add_argument('--upstream-port', type=int, default=28443)
    parser.add_argument('--http-port', type=int, default=8080)
    parser.add_argument('--https-port', type=int, default=8443)
    parser.add_argument('--cert', default='certs/server.crt')
    parser.add_argument('--key', default='certs/server.key')
    parser.add_argument('--logs', type=Path, default=Path('proxy-logs'))
    args = parser.parse_args()
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass
    except OSError as error:
        parser.exit(1, f'Cannot start listener: {error}\n')


if __name__ == '__main__':
    main()

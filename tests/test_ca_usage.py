"""
TLS integration tests — verify that generated certificates work in real TLS connections.

Uses asyncio TCP server/client with ssl.SSLContext to test end-to-end TLS.
"""

from asyncio import CancelledError, Event, create_subprocess_exec, create_task, open_connection, start_server
from asyncio.subprocess import PIPE
from ssl import SSLCertVerificationError, SSLContext, PROTOCOL_TLS_SERVER, create_default_context

from pytest import mark, raises

from simple_ca import CA


def _write_ckp(tmp_path, prefix, ckp):
    """Write cert and key PEM files, return (cert_path, key_path)."""
    cert_path = tmp_path / f'{prefix}.cert'
    key_path = tmp_path / f'{prefix}.key'
    cert_path.write_text(ckp.cert)
    key_path.write_text(ckp.key)
    return cert_path, key_path


async def _run_tls_echo_server(server_ctx, host, port, ready_event):
    """Echo server — reads data from client, sends it back, then closes."""

    async def handle_client(reader, writer):
        data = await reader.read(4096)
        writer.write(data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await start_server(handle_client, host, port, ssl=server_ctx)
    actual_port = server.sockets[0].getsockname()[1]
    ready_event.port = actual_port
    ready_event.set()
    async with server:
        await server.serve_forever()


async def _run_tls_http_server(server_ctx, host, port, ready_event):
    """Minimal HTTPS server — responds with 'Hello, world!\\n' to any request."""

    async def handle_client(reader, writer):
        # Read HTTP request headers until blank line
        while True:
            line = await reader.readline()
            if line in (b'\r\n', b'\n', b''):
                break
        body = b'Hello, world!\n'
        response = (
            b'HTTP/1.1 200 OK\r\n'
            b'Content-Length: ' + str(len(body)).encode() + b'\r\n'
            b'Connection: close\r\n'
            b'\r\n'
            + body
        )
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await start_server(handle_client, host, port, ssl=server_ctx)
    actual_port = server.sockets[0].getsockname()[1]
    ready_event.port = actual_port
    ready_event.set()
    async with server:
        await server.serve_forever()


@mark.asyncio
async def test_tls_echo(tmp_path):
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME', san=['localhost'])

    ca_cert_path, _ = _write_ckp(tmp_path, 'ca', ca)
    server_cert_path, server_key_path = _write_ckp(tmp_path, 'server', sc)

    server_ctx = SSLContext(PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert_path, server_key_path, password=sc.key_password)

    client_ctx = create_default_context(cafile=str(ca_cert_path))

    ready_event = Event()
    server_task = create_task(_run_tls_echo_server(server_ctx, '127.0.0.1', 0, ready_event))

    try:
        await ready_event.wait()
        port = ready_event.port

        reader, writer = await open_connection('127.0.0.1', port, ssl=client_ctx, server_hostname='localhost')
        writer.write(b'hello TLS')
        await writer.drain()

        data = await reader.read(4096)
        assert data == b'hello TLS'

        writer.close()
        await writer.wait_closed()
    finally:
        server_task.cancel()
        try:
            await server_task
        except CancelledError:
            pass


@mark.asyncio
async def test_tls_san_ip(tmp_path):
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='myserver', org='ACME', san=['IP:127.0.0.1'])

    ca_cert_path, _ = _write_ckp(tmp_path, 'ca', ca)
    server_cert_path, server_key_path = _write_ckp(tmp_path, 'server', sc)

    server_ctx = SSLContext(PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert_path, server_key_path, password=sc.key_password)

    client_ctx = create_default_context(cafile=str(ca_cert_path))
    client_ctx.check_hostname = False

    ready_event = Event()
    server_task = create_task(_run_tls_echo_server(server_ctx, '127.0.0.1', 0, ready_event))

    try:
        await ready_event.wait()
        port = ready_event.port

        reader, writer = await open_connection('127.0.0.1', port, ssl=client_ctx, server_hostname='127.0.0.1')
        writer.write(b'hello IP SAN')
        await writer.drain()

        data = await reader.read(4096)
        assert data == b'hello IP SAN'

        writer.close()
        await writer.wait_closed()
    finally:
        server_task.cancel()
        try:
            await server_task
        except CancelledError:
            pass


@mark.asyncio
async def test_tls_intermediate_ca(tmp_path):
    """TLS with intermediate CA — server must send fullchain (cert_chain)."""
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME', cn='Intermediate CA')
    sc = inter.create_server_cert(cn='localhost', org='ACME', san=['localhost'])

    # Client trusts only root CA
    root_cert_path = tmp_path / 'root.pem'
    root_cert_path.write_text(root.cert)

    # Server uses fullchain (server cert + intermediate cert)
    fullchain_path = tmp_path / 'fullchain.pem'
    fullchain_path.write_text(sc.cert_chain)
    server_key_path = tmp_path / 'server.key'
    server_key_path.write_text(sc.key)

    server_ctx = SSLContext(PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(fullchain_path, server_key_path, password=sc.key_password)

    client_ctx = create_default_context(cafile=str(root_cert_path))

    ready_event = Event()
    server_task = create_task(_run_tls_echo_server(server_ctx, '127.0.0.1', 0, ready_event))

    try:
        await ready_event.wait()
        port = ready_event.port

        reader, writer = await open_connection('127.0.0.1', port, ssl=client_ctx, server_hostname='localhost')
        writer.write(b'hello intermediate TLS')
        await writer.drain()

        data = await reader.read(4096)
        assert data == b'hello intermediate TLS'

        writer.close()
        await writer.wait_closed()
    finally:
        server_task.cancel()
        try:
            await server_task
        except CancelledError:
            pass


@mark.asyncio
async def test_tls_intermediate_ca_without_fullchain_rejected(tmp_path):
    """Without fullchain, client cannot verify the server cert signed by intermediate CA."""
    root = CA.init_ca(org='ACME', cn='Root CA')
    inter = root.create_intermediate_ca(org='ACME', cn='Intermediate CA')
    sc = inter.create_server_cert(cn='localhost', org='ACME', san=['localhost'])

    root_cert_path = tmp_path / 'root.pem'
    root_cert_path.write_text(root.cert)

    # Server sends only server cert, NOT fullchain
    server_cert_path, server_key_path = _write_ckp(tmp_path, 'server', sc)

    server_ctx = SSLContext(PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert_path, server_key_path, password=sc.key_password)

    client_ctx = create_default_context(cafile=str(root_cert_path))

    ready_event = Event()
    server_task = create_task(_run_tls_echo_server(server_ctx, '127.0.0.1', 0, ready_event))

    try:
        await ready_event.wait()
        port = ready_event.port

        with raises(SSLCertVerificationError):
            reader, writer = await open_connection('127.0.0.1', port, ssl=client_ctx, server_hostname='localhost')
    finally:
        server_task.cancel()
        try:
            await server_task
        except CancelledError:
            pass


@mark.asyncio
async def test_tls_wrong_ca_rejected(tmp_path):
    ca1 = CA.init_ca(org='ACME-1')
    ca2 = CA.init_ca(org='ACME-2')
    sc = ca1.create_server_cert(cn='localhost', org='ACME-1', san=['localhost', '127.0.0.1'])

    # Client trusts ca2, but server cert is signed by ca1
    ca2_cert_path, _ = _write_ckp(tmp_path, 'ca2', ca2)
    server_cert_path, server_key_path = _write_ckp(tmp_path, 'server', sc)

    server_ctx = SSLContext(PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert_path, server_key_path, password=sc.key_password)

    client_ctx = create_default_context(cafile=str(ca2_cert_path))

    ready_event = Event()
    server_task = create_task(_run_tls_echo_server(server_ctx, '127.0.0.1', 0, ready_event))

    try:
        await ready_event.wait()
        port = ready_event.port

        with raises(SSLCertVerificationError):
            reader, writer = await open_connection('127.0.0.1', port, ssl=client_ctx, server_hostname='localhost')
    finally:
        server_task.cancel()
        try:
            await server_task
        except CancelledError:
            pass


@mark.asyncio
async def test_https_curl(tmp_path):
    """HTTPS test using curl as the client — verifies certificates work with real tools."""
    ca = CA.init_ca(org='ACME')
    sc = ca.create_server_cert(cn='localhost', org='ACME', san=['localhost'])

    ca_cert_path = tmp_path / 'ca.pem'
    ca_cert_path.write_text(ca.cert)
    server_cert_path, server_key_path = _write_ckp(tmp_path, 'server', sc)

    server_ctx = SSLContext(PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(server_cert_path, server_key_path, password=sc.key_password)

    ready_event = Event()
    server_task = create_task(_run_tls_http_server(server_ctx, '127.0.0.1', 0, ready_event))

    try:
        await ready_event.wait()
        port = ready_event.port

        proc = await create_subprocess_exec(
            'curl', '--cacert', str(ca_cert_path), f'https://localhost:{port}/',
            stdout=PIPE, stderr=PIPE,
        )
        stdout, stderr = await proc.communicate()
        assert proc.returncode == 0, f'curl failed: {stderr.decode()}'
        assert stdout == b'Hello, world!\n'
    finally:
        server_task.cancel()
        try:
            await server_task
        except CancelledError:
            pass

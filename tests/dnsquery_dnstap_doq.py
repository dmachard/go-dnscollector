import unittest
import asyncio
import requests
import re

class CollectorProc(asyncio.SubprocessProtocol):
    def __init__(self, is_ready, is_clientresponse):
        self.is_ready = is_ready
        self.is_clientresponse = is_clientresponse
        self.transport = None
        self.proc = None

    def connection_made(self, transport):
        self.transport = transport
        self.proc = transport.get_extra_info('subprocess')

    def pipe_data_received(self, fd, data):
        print(data.decode(), end="")

        if b"receiver framestream initialized" in data:
            self.is_ready.set_result(True)

        if not self.is_clientresponse.done():
            if b"CLIENT_RESPONSE NOERROR" in data:
                self.is_clientresponse.set_result(True)
                self.kill()

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass

class DoQClient(asyncio.SubprocessProtocol):
    def __init__(self, exit_future):
        self.exit_future = exit_future
        self.transport = None
        self.proc = None

    def connection_made(self, transport):
        self.transport = transport
        self.proc = transport.get_extra_info('subprocess')

    def pipe_data_received(self, fd, data):
        print(data.decode(), end="")

    def process_exited(self):
        self.exit_future.set_result(True)

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass

class TestBench(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()

    def test_stdout_recv(self):
        """benchmark"""
        async def run():
            # run collector
            is_ready = asyncio.Future()
            is_clientresponse = asyncio.Future()
            args = ( "./go-dnscollector", "-config", "./testsdata/config_stdout_dnstap_doq.yml",)
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: CollectorProc(is_ready, is_clientresponse),
                                                                                       *args, stdout=asyncio.subprocess.PIPE)

            # wait if is listening
            try:
                await asyncio.wait_for(is_ready, timeout=1.5)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("collector listening timeout")
            

            nb_packets = [10]
            for nb in nb_packets:
                # start gen
                is_existed = asyncio.Future()
                args = ( "./q", "www.github.com", "A", "@quic://127.0.0.1:853", "--tls-insecure-skip-verify")
                transport_client, protocol_client =  await self.loop.subprocess_exec(lambda: DoQClient(is_existed), *args, stdout=asyncio.subprocess.PIPE)
                await is_existed

                protocol_client.kill()
                transport_client.close()

            # Shutdown all
            protocol_collector.kill()
            transport_collector.close()


        self.loop.run_until_complete(run())

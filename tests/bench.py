import unittest
import asyncio
import requests

class CollectorProc(asyncio.SubprocessProtocol):
    def __init__(self, is_listening):
        self.is_listening = is_listening
        self.transport = None
        self.proc = None

    def connection_made(self, transport):
        self.transport = transport
        self.proc = transport.get_extra_info('subprocess')

    def pipe_data_received(self, fd, data):
        print(data.decode(), end="")

        if b"collector dnstap tcp - is listening on" in data:
            self.is_listening.set_result(True)

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass

class GeneratorProc(asyncio.SubprocessProtocol):
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
            is_listening = asyncio.Future()
            args = ( "./go-dnscollector", "-config", "./tests/config_metrics_dnstaptcp.yml",)
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: CollectorProc(is_listening),
                                                                                       *args, stdout=asyncio.subprocess.PIPE)

            # wait if is listening
            try:
                await asyncio.wait_for(is_listening, timeout=1.5)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("collector listening timeout")
            

            # start gen
            is_existed = asyncio.Future()
            args = ( "./../gen/go-dnstap-generator", "-n", "1000000")
            transport_gen, protocol_gen =  await self.loop.subprocess_exec(lambda: GeneratorProc(is_existed),
                                                                                       *args, stdout=asyncio.subprocess.PIPE)
            await is_existed


            r = requests.get("http://127.0.0.1:8080/metrics", auth=('admin', 'changeme'))
            print(r.text)

            # Shutdown all
            protocol_collector.kill()
            transport_collector.close()
            protocol_gen.kill()
            transport_gen.close()


        self.loop.run_until_complete(run())

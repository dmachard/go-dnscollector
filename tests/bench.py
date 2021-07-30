import unittest
import asyncio
import requests
import re

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
            

            nb_packets = [10000, 50000, 100000, 500000, 1000000, 2000000]
            for nb in nb_packets:
                print("STARTING BENCHMARK: %s packets" % nb)
                # start gen
                is_existed = asyncio.Future()
                args = ( "./../gen/go-dnstap-generator", "-c", "2", "-n", str(nb) )
                transport_gen, protocol_gen =  await self.loop.subprocess_exec(lambda: GeneratorProc(is_existed),
                                                                                        *args, stdout=asyncio.subprocess.PIPE)
                await is_existed


                r = requests.get("http://127.0.0.1:8080/metrics", auth=('admin', 'changeme'))
                for l in r.text.splitlines():
                    if l.startswith("dnscollector_domains_total"): print(l)
                    if l.startswith("dnscollector_clients_total"): print(l)
                    if l.startswith("dnscollector_pps_max"): print(l)
                    if l.startswith("dnscollector_pps_max"): print(l)
                    if l.startswith("dnscollector_queries_total"): print(l)
                    if l.startswith("dnscollector_replies_total"): print(l)


                protocol_gen.kill()
                transport_gen.close()
                print("ENDING BENCHMARK: %s packets" % nb)

            # Shutdown all
            protocol_collector.kill()
            transport_collector.close()


        self.loop.run_until_complete(run())

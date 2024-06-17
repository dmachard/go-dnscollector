
import unittest
import asyncio

class ProcessProtocol(asyncio.SubprocessProtocol):
    def __init__(self, is_configvalid, is_configerror):
        self.is_configvalid = is_configvalid
        self.is_configerror = is_configerror
        self.transport = None
        self.proc = None

    def connection_made(self, transport):
        self.transport = transport
        self.proc = transport.get_extra_info('subprocess')

    def pipe_data_received(self, fd, data):
        print(data.decode(), end="")

        if b"main - running" in data:
            self.is_configvalid.set_result(True)
            self.kill()
        
        if b"config error" in data:
            self.is_configerror.set_result(True)
            self.kill()

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass

class TestConfig(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()

    def test1_valid(self):
        """test valid config"""
        async def run():
            # run collector
            is_configvalid= asyncio.Future()
            args = ( "./go-dnscollector", "-config", "./tests/testsdata/config_verbose.yml",)
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: ProcessProtocol(is_configvalid, None),
                                                                                        *args, stdout=asyncio.subprocess.PIPE)

            # wait if is listening
            try:
                await asyncio.wait_for(is_configvalid, timeout=1.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("config loaded timeout")

            # cleanup all
            protocol_collector.kill()
            transport_collector.close()

        self.loop.run_until_complete(run())

    def test2_invalid(self):
        """test invalid config"""
        async def run():
            # run collector
            is_configinvalid= asyncio.Future()
            args = ( "./go-dnscollector", "-config", "./tests/testsdata/config_invalid.yml",)
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: ProcessProtocol(None, is_configinvalid),
                                                                                        *args, stdout=asyncio.subprocess.PIPE)

            # wait if is listening
            try:
                await asyncio.wait_for(is_configinvalid, timeout=1.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("config error timeout")

            # cleanup all
            protocol_collector.kill()
            transport_collector.close()
            
        self.loop.run_until_complete(run())

    def test3_default_config(self):
        """test the default config"""
        async def run():
            # run collector
            is_configvalid= asyncio.Future()
            args = ( "./go-dnscollector", )
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: ProcessProtocol(is_configvalid, None),
                                                                                        *args, stdout=asyncio.subprocess.PIPE)

            # wait if is listening
            try:
                await asyncio.wait_for(is_configvalid, timeout=1.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("config loaded timeout")

            # cleanup all
            protocol_collector.kill()
            transport_collector.close()

        self.loop.run_until_complete(run())
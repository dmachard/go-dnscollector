import unittest
import asyncio
import dns.resolver

my_resolver = dns.resolver.Resolver(configure=False)
my_resolver.nameservers = ['127.0.0.1']
my_resolver.port = 5553
my_resolver.timeout = 20
my_resolver.lifetime = 20

class ProcessProtocol(asyncio.SubprocessProtocol):
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

        if b"new connection" in data:
            self.is_ready.set_result(True)
        
        if not self.is_clientresponse.done():
            if b"CLIENT_RESPONSE NOERROR" in data:
                self.is_clientresponse.set_result(True)
                self.kill()

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass
        

class TestPowerDNS(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()

    def test_stdout_recv(self):
        """test to receive protobuf powerdns response in stdout"""
        async def run():
            # run collector
            is_ready = asyncio.Future()
            is_clientresponse = asyncio.Future()
            args = ( "./go-dnscollector", "-config", "./testsdata/config_stdout_powerdns.yml",)
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: ProcessProtocol(is_ready, is_clientresponse),
                                                                                       *args, stdout=asyncio.subprocess.PIPE)

            # make some dns queries to force the dns server to connect to the collector
            # in some products (dnsdist), connection is after  incoming dns traffic
            for i in range(20):
                try:
                    my_resolver.resolve('www.github.com', 'a')
                except: pass

            # waiting for connection between collector and dns server is ok
            try:
                await asyncio.wait_for(is_ready, timeout=5.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                transport_collector.close()
                self.fail("collector timeout")

            # make some dns queries
            for i in range(20):
                try:
                    my_resolver.resolve('www.github.com', 'a')
                except: pass
                
            # wait client response on collector
            try:
                await asyncio.wait_for(is_clientresponse, timeout=30.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                transport_collector.close()
                self.fail("log client response expected")

            # Shutdown all
            protocol_collector.kill()
            transport_collector.close()


        self.loop.run_until_complete(run())

import unittest
import asyncio
import fstrm
import dnstap_pb
import dns.message
import socket

class DnstapProtocol(asyncio.Protocol):
    def __init__(self, handshake):
        self.handshake = handshake
        self.transport = None

        self.content_type = b"protobuf:dnstap.Dnstap"
        self.fstrm = fstrm.FstrmCodec()

    def connection_made(self, transport):
        """handshake"""
        self.transport = transport
        self.transport.write(self.fstrm.encode_ctrlready(self.content_type))

    def data_received(self, data):
        if not self.handshake.done():
            if self.fstrm.is_ctrlaccept(data):
                self.transport.write(self.fstrm.encode_ctrlstart(self.content_type))
                self.handshake.set_result(True)

    def send_clientquery(self):

        dnsquery = dns.message.make_query('www.google.com.', dns.rdatatype.A)

        dnstap = dnstap_pb.Dnstap()
        dnstap.type = 1
        dnstap.version = b"-"
        dnstap.identity = b"dnscollector"
        dnstap.message.type = dnstap_pb.dnstap_pb2._MESSAGE_TYPE.values_by_name["CLIENT_QUERY"].number
        dnstap.message.socket_protocol = dnstap_pb.dnstap_pb2._SOCKETPROTOCOL.values_by_name["UDP"].number
        dnstap.message.socket_family = dnstap_pb.dnstap_pb2._SOCKETFAMILY.values_by_name["INET"].number

        dnstap.message.query_address = socket.inet_pton(socket.AF_INET, "127.0.0.1")
        dnstap.message.query_port = 45600
        dnstap.message.response_address = socket.inet_pton(socket.AF_INET, "127.0.0.2")
        dnstap.message.response_port = 53

        dnstap.message.query_message = dnsquery.to_wire()

        self.transport.write(self.fstrm.encode_data(data=dnstap.SerializeToString()))

class ProcessProtocol(asyncio.SubprocessProtocol):
    def __init__(self, is_listening, is_clientquery):
        self.is_listening = is_listening
        self.is_clientquery = is_clientquery
        self.transport = None
        self.proc = None

    def connection_made(self, transport):
        self.transport = transport
        self.proc = transport.get_extra_info('subprocess')

    def pipe_data_received(self, fd, data):
        print(data.decode(), end="")

        if b"dnstap collector - is listening on" in data:
            self.is_listening.set_result(True)
        
        if b"CLIENT_QUERY NOERROR" in data:
            self.is_clientquery.set_result(True)
            self.kill()

    def kill(self):
        try:
            self.proc.kill()
        except ProcessLookupError: pass
        

class TestDnstap(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()

    def test1_stdout_recv(self):
        """test to receive dnstap query in stdout"""
        async def run():
            # run collector
            is_listening = asyncio.Future()
            is_clientquery = asyncio.Future()
            args = ( "./go-dnscollector", "-config", "./testsdata/config_stdout_dnstapunix.yml",)
            transport_collector, protocol_collector =  await self.loop.subprocess_exec(lambda: ProcessProtocol(is_listening, is_clientquery),
                                                                                       *args, stdout=asyncio.subprocess.PIPE)

            # wait if is listening
            try:
                await asyncio.wait_for(is_listening, timeout=1.5)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("collector listening timeout")

            # connect client to collector
            hanshake_client = self.loop.create_future()
            transport_client, protocol_client =  await self.loop.create_unix_connection(lambda: DnstapProtocol(hanshake_client), '/tmp/dnstap.sock')

            # wait handshake from collector
            try:
                await asyncio.wait_for(hanshake_client, timeout=1.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("handshake client failed")

            # send dnstap clientquery
            protocol_client.send_clientquery()

            # wait client query on collector
            try:
                await asyncio.wait_for(is_clientquery, timeout=1.0)
            except asyncio.TimeoutError:
                protocol_collector.kill()
                self.fail("dnstap client query expected")

            # Shutdown all
            transport_client.close()
            protocol_collector.kill()
            transport_collector.close()

        self.loop.run_until_complete(run())


            
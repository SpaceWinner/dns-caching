from unittest import TestCase, main
from dns_parser import DnsPacket, QueryType


class DnsPacketTest(TestCase):
    packets = [b'\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x31\x01\x31'
               b'\x03\x31\x36\x38\x03\x31\x39\x32\x07\x69\x6e'
               b'\x2d\x61\x64\x64\x72\x04\x61\x72\x70\x61\x00\x00\x0c\x00\x01',

               b'\x00\x02\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02\x65\x31\x02\x72\x75\x00\x00\x02\x00\x01',

               b'\x00\x02\x81\x80\x00\x01\x00\x04\x00\x00\x00\x00\x02\x65\x31\x02'
               b'\x72\x75\x00\x00\x02\x00\x01\xc0\x0c\x00\x02\x00\x01\x00\x00\x01'
               b'\x2c\x00\x0a\x03\x6e\x73\x32\x03\x6e\x67\x73\xc0\x0f\xc0\x0c\x00'
               b'\x02\x00\x01\x00\x00\x01\x2c\x00\x05\x02\x6e\x73\xc0\x27\xc0\x0c'
               b'\x00\x02\x00\x01\x00\x00\x01\x2c\x00\x06\x03\x6e\x73\x31\xc0\x0c'
               b'\xc0\x0c\x00\x02\x00\x01\x00\x00\x01\x2c\x00\x06\x03\x6e\x73\x32'
               b'\xc0\x0c'

               ]

    def _test_packet(self, expected, index):
        packet = DnsPacket.from_bytes(DnsPacketTest.packets[index])

        self.assertEqual(packet.id, expected.id)
        self.assertEqual(packet.has_error, expected.has_error)
        self.assertEqual(packet.is_authoritative, expected.is_authoritative)
        self.assertEqual(packet.is_recursion_desired, expected.is_recursion_desired)
        self.assertEqual(packet.is_recursion_available, expected.is_recursion_available)
        self.assertEqual(packet.is_response, expected.is_response)
        self.assertEqual(packet.is_truncated, expected.is_truncated)
        self.assertEqual(packet.opcode, expected.opcode)
        self.assertEqual(packet.question, expected.question)
        self.assertEqual(packet.answers, expected.answers)

    def test_parse_ptr_question(self):
        expected = DnsPacket(id_=1, is_authoritative=False, is_response=False, opcode=0, is_truncated=False,
                             is_recursion_desired=True, is_recursion_available=False,
                             question=(b'1.1.168.192.in-addr.arpa', QueryType.PTR), answers=(), has_error=False)
        self._test_packet(expected, 0)

    def test_parse_ns_question(self):
        expected = DnsPacket(id_=2, is_authoritative=False, is_response=False, opcode=0, is_truncated=False,
                             is_recursion_desired=True, is_recursion_available=False, question=(b'e1.ru', QueryType.NS),
                             answers=(), has_error=False)
        self._test_packet(expected, 1)

    def test_parse_ns_answers(self):
        answers = [
            (b'e1.ru', QueryType.NS, 300, b'\x03ns2\x03ngs\xc0\x0f'),
            (b'e1.ru', QueryType.NS, 300, b"\x02ns\xc0'"),
            (b'e1.ru', QueryType.NS, 300, b'\x03ns1\xc0\x0c'),
            (b'e1.ru', QueryType.NS, 300, b'\x03ns2\xc0\x0c')
        ]
        expected = DnsPacket(id_=2, is_authoritative=False, is_response=True, opcode=0, is_truncated=False,
                             is_recursion_available=True, is_recursion_desired=True, question=(b'e1.ru', QueryType.NS),
                             answers=tuple(answers), has_error=False)
        self._test_packet(expected, 2)

    def test_serialize_ptr_question(self):
        packet = DnsPacketTest.packets[0]
        parsed = DnsPacket.from_bytes(packet)
        serialized = bytes(parsed)
        self.assertEqual(len(serialized), len(packet))
        self.assertEqual(serialized, packet)

    def test_serialize(self):
        for packet in DnsPacketTest.packets:
            parsed = DnsPacket.from_bytes(packet)
            serialized = bytes(parsed)
            self.assertEqual(serialized, packet)


if __name__ == '__main__':
    main()

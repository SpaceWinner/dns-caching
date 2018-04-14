from struct import unpack, pack
from enum import IntEnum


def read_bit(flags, position):
    return ((1 << position) & flags) != 0


def squash_bits(bits):
    bits = list(map(int, reversed(bits)))
    return sum((bit << i) for i, bit in enumerate(bits))


class QueryType(IntEnum):
    A = 1
    NS = 2
    CNAME = 5
    PTR = 12
    HINFO = 13
    MX = 15
    AXFR = 252
    ANY = 255


class DnsPacket:
    def __init__(self, id_, is_authoritative, is_response, opcode,
                 is_truncated, question, answers, is_recursion_desired, is_recursion_available, has_error):
        self.id = id_
        self.question = question
        self.answers = answers
        self.is_authoritative = is_authoritative
        self.is_response = is_response
        self.opcode = opcode
        self.is_truncated = is_truncated
        self.is_recursion_desired = is_recursion_desired
        self.is_recursion_available = is_recursion_available
        self.has_error = has_error

    @staticmethod
    def read_flags(flags):
        (is_response, op1, op2, op3, op4, is_authoritative, is_truncated,
            rd, ra, _, _, _, r1, r2, r3, r4) = map(lambda i: read_bit(flags, 15-i), range(16))
        opcode = squash_bits([op1, op2, op3, op4])
        has_error = squash_bits([r1, r2, r3, r4]) == 3

        return is_response, opcode, is_authoritative, is_truncated, rd, ra, has_error

    def flags2bytes(self):
        bits = [self.is_response]
        bits.extend(map(lambda x: read_bit(self.opcode, x), range(4)))
        bits.extend([
            self.is_authoritative,
            self.is_truncated,
            self.is_recursion_desired,
            self.is_recursion_available
        ])
        bits.extend([False] * 3)
        bits.extend([False, False, True, True] if self.has_error else [False] * 4)
        return squash_bits(bits)

    @staticmethod
    def read_domain_name(bts, all_bts):
        query_parts = []
        count = bts[0]
        while count != 0:
            if count > 63:
                query_parts.append(DnsPacket.read_domain_name(all_bts[bts[1]:], all_bts)[0])
                bts = bts[2:]
                break
            else:
                query_parts.append(bts[1:count + 1])
                bts = bts[count + 1:]
                count = bts[0]
        return b'.'.join(query_parts), bts

    @staticmethod
    def read_question(bts):
        name, bts = DnsPacket.read_domain_name(bts, bts)
        query_type, query_class = unpack('>HH', bts[1:5])
        return bts[5:], name, QueryType(query_type)

    @staticmethod
    def read_answer(bts, all_bts):
        _, query_type, _, ttl, data_length = unpack('>H H H I H', bts[:12])
        data = bts[12:12+data_length]

        name, _ = DnsPacket.read_domain_name(bts, all_bts)
        return bts[12+data_length:], name, QueryType(query_type), ttl, data

    @staticmethod
    def from_bytes(bts):
        id_, flags, qcount, answer_count, authority_count, additional_count = unpack('> H H H H H H', bts[:12])
        is_response, opcode, is_authoritative, is_truncated, rd, ra, has_error = DnsPacket.read_flags(flags)
        question = None
        answers = []
        all_bts = bts
        bts = bts[12:]
        if qcount == 1:
            bts, *question = DnsPacket.read_question(bts)
        for i in range(answer_count):
            bts, *answer = DnsPacket.read_answer(bts, all_bts)
            answers.append(tuple(answer))
        return DnsPacket(id_, is_authoritative, is_response, opcode, is_truncated,
                         tuple(question), tuple(answers), rd, ra, has_error)

    @staticmethod
    def domain_name2bytes(domain_name, index, domains):
        acc = domain_name.split(b'.')
        result = b''
        for part in domain_name.split(b'.'):
            if tuple(acc) in domains:
                return result + domains[tuple(acc)]
            domains[tuple(acc)] = bytes([0xc0, index])
            index += len(part) + 1
            result += bytes([len(part)]) + part
            acc.pop(0)
        return result + b'\00'

    def __bytes__(self):
        flags = self.flags2bytes()
        bts = pack('> H H H H H H', self.id, flags, 1, len(self.answers), 0, 0)
        domains = {}
        bts += DnsPacket.domain_name2bytes(self.question[0], len(bts), domains)
        bts += pack('> HH', int(self.question[1]), 1)
        for name, query_type, ttl, data in self.answers:
            bts += DnsPacket.domain_name2bytes(name, len(bts), domains)
            bts += pack('> H H I H', int(query_type), 1, ttl, len(data))
            bts += data
        return bts


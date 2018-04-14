from socket import socket, SOCK_DGRAM, AF_INET, timeout as sockettimeout
from traceback import format_exc
from threading import Thread
from signal import signal, SIGTERM, SIGINT
from cache import load, save
from dns_parser import DnsPacket


class DnsServer:
    def __init__(self):
        self.cache = load()
        self.endpoint = '127.0.0.1', 53
        self.origin = '8.8.8.8', 53

    def run(self):
        signal(SIGINT, self.on_exit)
        signal(SIGTERM, self.on_exit)
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.bind(self.endpoint)
        print('>> Running dns-cache on: {}:{}'.format(*self.endpoint))
        sock.settimeout(0.5)
        while 1:
            try:
                data, addr = sock.recvfrom(4096)
                t = Thread(target=self.on_connection, args=(sock, data, addr))
                t.daemon = True
                t.start()
            except sockettimeout:
                pass

    def forward_question(self, packet):
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(12)
        sock.sendto(bytes(packet), self.origin)
        data, addr = sock.recvfrom(4096)
        return DnsPacket.from_bytes(data)

    def on_connection(self, sock, data, addr):
        try:
            print('>> Data received')
            packet = DnsPacket.from_bytes(data)
            name, query_type = packet.question
            print('>> Question: ', query_type, name)
            cache_key = int(query_type), name
            if cache_key in self.cache:
                print('>> Found fresh record in cache')
                sock.sendto(self.cache[cache_key], addr)
            else:
                print('>> No fresh record in cache')
                origin_packet = self.forward_question(packet)
                if not origin_packet.answers:
                    print('>> Origin has no answers')
                    return
                min_ttl = min(origin_packet.answers, key=lambda x: x[2])[2]
                self.cache.add(cache_key, bytes(origin_packet), min_ttl)
                sock.sendto(bytes(origin_packet), addr)
            print('>> Answered')
        except:
            print('>> Error with packet: {}\n{}'.format(repr(data), format_exc()))

    def on_exit(self, _, __):
        save(self.cache)
        quit()


if __name__ == '__main__':
    DnsServer().run()

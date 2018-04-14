from time import time
from os.path import isfile


class Cache:
    def __init__(self, get_time, entries):
        self.get_time = get_time
        self.entries = entries

    def add(self, key, value, ttl):
        self.entries[key] = self.get_time() + ttl, value

    def __contains__(self, key):
        timestamp, _ = self.entries.get(key, (self.get_time() - 1, 0))
        return timestamp >= self.get_time()

    def __getitem__(self, key):
        _, value = self.entries[key]
        return value

    def __repr__(self):
        return f'Cache({repr(self.entries)})'

    def save_to_file(self, file):
        file.write(repr(self.entries))

    @staticmethod
    def from_file(file, get_time=None):
        entries = eval(file.read())
        return Cache(get_time or (lambda: int(time())), entries)


def load():
    if not isfile('cache.tmp'):
        return Cache((lambda: int(time())), {})
    with open('cache.tmp') as file:
        return Cache.from_file(file)


def save(cache):
    with open('cache.tmp', 'w') as file:
        return cache.save_to_file(file)

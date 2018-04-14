from unittest import TestCase, main
from cache import Cache
from io import StringIO


class CacheTest(TestCase):
    def test_ttl(self):
        current_time = 0
        cache = Cache(lambda: current_time, {})
        cache.add('key', 'value', 1)

        current_time = 1
        has_value = 'key' in cache
        current_time = 2
        has_value2 = 'key' in cache

        self.assertTrue(has_value)
        self.assertFalse(has_value2)

    def test_save_read(self):
        cache = Cache(lambda: 0, {})
        cache.add('key1', 'value1', 10)
        cache.add('key2', 'value2', 20)
        write_file = StringIO()
        cache.save_to_file(write_file)
        read_file = StringIO(write_file.getvalue())
        read_cache = Cache.from_file(read_file, lambda: 0)

        self.assertEqual(read_cache['key1'], 'value1')
        self.assertEqual(read_cache['key2'], 'value2')
        self.assertTrue('key1' in read_cache)
        self.assertTrue('key2' in read_cache)


if __name__ == '__main__':
    main()

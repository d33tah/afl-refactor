#!/usr/bin/env python

import unittest
import ctypes

try:
    from unittest import mock
except ImportError:
    import mock


# we'll be working both with bytearrays and ctypes strings.
# this one makes it more convenient to do so.
def O(x):
    return x if isinstance(x, int) else ord(x)


def has_new_bits(current, virgin):
    n = min([len(current), len(virgin)])
    for i in range(n):
        if O(current[i]) & O(virgin[i]):
            virgin[i] = chr(O(virgin[i]) & O(current[i]))
            return True
    return False


def count_bits(mem):
    return sum(bin(O(x)).count('1') for x in mem)


def setup_shm(mem_size):

    IPC_PRIVATE, IPC_CREAT, IPC_EXCL = 0, 512, 1024

    shmget = ctypes.cdll.LoadLibrary("libc.so.6").shmget
    shmat = ctypes.cdll.LoadLibrary("libc.so.6").shmat
    shmat.restype = ctypes.POINTER(ctypes.c_char * mem_size)

    perms = IPC_CREAT | IPC_EXCL | 0o600
    shm_id = shmget(IPC_PRIVATE, mem_size, perms)
    if shm_id < 0:
        raise RuntimeError('shmget failed with return value %d' % shm_id)

    try:
        trace_bits = shmat(shm_id, 0, 0)[0]
    except ValueError:
        # NULL pointer access
        raise RuntimeError('shmat failed, returning NULL pointer')

    return shm_id, trace_bits


class HasNewBitsTest(unittest.TestCase):
    def test_returns_false_if_current_is_zero(self):
        self.assertFalse(has_new_bits(bytearray([0]), bytearray([1])))

    def test_returns_true_is_have_common_bits(self):
        self.assertTrue(has_new_bits(bytearray([2]), bytearray([3])))

    def test_updates_virgin_bits_if_common_bits(self):
        virgin = bytearray([3])
        has_new_bits(bytearray([2]), virgin)
        self.assertEqual(virgin[0], 2)

    def test_updates_virgin_bits_if_common_bits_and_virgin_is_ctypes_string(self):
        virgin = ctypes.create_string_buffer(1)
        virgin[0] = '\x03'
        has_new_bits(bytearray([2]), virgin)
        self.assertEqual(virgin[0], '\x02')


class CountBitsTest(unittest.TestCase):
    def test_returns_zero_for_empty(self):
        self.assertEqual(0, count_bits(bytearray()))

    def test_returns_one_for_one(self):
        self.assertEqual(1, count_bits(bytearray([1])))

    def test_returns_four_for_one_and_seven(self):
        self.assertEqual(4, count_bits(bytearray([1, 7])))

    def test_returns_four_for_one_and_seven_and_buf_is_ctypes_string(self):
        buf = ctypes.create_string_buffer(2)
        buf[0] = '\x01'
        buf[1] = '\x07'
        self.assertEqual(4, count_bits(buf))


class SetupSHMTest(unittest.TestCase):

    def setUp(self):
        self.mock_shmget = mock.Mock()
        self.mock_shmat = mock.Mock()
        self.mock_shmat.return_value = [ctypes.create_string_buffer(1)]

        def mock_load_library_side_effect(lib):
            return mock.Mock(shmget=self.mock_shmget,
                             shmat=self.mock_shmat)
        self.patcher = mock.patch('ctypes.cdll.LoadLibrary')
        mock_load_library = self.patcher.start()
        mock_load_library.side_effect = mock_load_library_side_effect

    def tearDown(self):
        self.patcher.stop()

    def test_calls_shmget(self):
        setup_shm(1)
        self.mock_shmget.assert_called()

    def test_calls_shmat(self):
        setup_shm(1)
        self.mock_shmat.assert_called()


if __name__ == '__main__':
    unittest.main()

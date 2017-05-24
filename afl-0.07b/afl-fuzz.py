#!/usr/bin/env python

import unittest
import ctypes
import os
import sys
import stat
import resource
# We need this one in order to be able to mock.patch self:
import __main__  # NOQA

try:
    from unittest import mock
except ImportError:
    import mock

MAX_FILESIZE = 1 * 1000 * 1000
DEV_NULL = open(os.devnull).fileno()
FAULT_NONE, FAULT_HANG, FAULT_CRASH, FAULT_ERROR = range(4)
EXEC_FAIL = 0x55
IPC_PRIVATE, IPC_CREAT, IPC_EXCL = 0, 512, 1024


# we'll be working both with bytearrays and ctypes strings.
# this one makes it more convenient to do so.
def O(x):
    return x if isinstance(x, int) else ord(x)

if sys.version.startswith('3'):
    def to_byte(x):
        return x
else:
    def to_byte(x):
        return chr(x)


def has_new_bits(current, virgin):
    n = min([len(current), len(virgin)])
    for i in range(n):
        if O(current[i]) & O(virgin[i]):
            virgin[i] = to_byte(O(virgin[i]) & O(current[i]))
            return True
    return False


def count_bits(mem):
    return sum(bin(O(x)).count('1') for x in mem)


def setup_shm(mem_size):

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
        virgin[0] = b'\x03'
        has_new_bits(bytearray([2]), virgin)
        self.assertEqual(virgin[0], b'\x02')


class CountBitsTest(unittest.TestCase):
    def test_returns_zero_for_empty(self):
        self.assertEqual(0, count_bits(bytearray()))

    def test_returns_one_for_one(self):
        self.assertEqual(1, count_bits(bytearray([1])))

    def test_returns_four_for_one_and_seven(self):
        self.assertEqual(4, count_bits(bytearray([1, 7])))

    def test_returns_four_for_one_and_seven_and_buf_is_ctypes_string(self):
        buf = ctypes.create_string_buffer(2)
        buf[0] = b'\x01'
        buf[1] = b'\x07'
        self.assertEqual(4, count_bits(buf))


class SetupSHMTest(unittest.TestCase):

    def setUp(self):
        self.mock_shmget = mock.Mock(return_value=0)
        self.mock_shmat = mock.Mock(return_value=0)
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
        self.mock_shmget.assert_called_once_with(0, 1, IPC_CREAT | IPC_EXCL | 0o600)

    def test_calls_shmat(self):
        setup_shm(1)
        self.mock_shmat.assert_called_once_with(0, 0, 0)


def read_testcases(in_dir, queue):
    """Read all testcases from the input directory, then queue them for testing."""
    for fname in os.listdir(in_dir):
        if not os.access(fname, os.R_OK):
            raise RuntimeError('Unable to open %s' % repr(fname))
        st = os.stat(fname)
        if not stat.S_ISREG(st.st_mode) or not st.st_size:
            continue
        if st.st_size > MAX_FILESIZE:
            raise RuntimeError('Test case %s is too big' % repr(fname))
        queue.append({'fname': fname, 'flen': st.st_size, 'keep': True, 'det_done': False})
    # NOTE: I removed the "No usable test cases" error - check it in main().


class ReadTestcasesTest(unittest.TestCase):

    @mock.patch('os.listdir')
    def test_calls_listdir(self, mock_listdir):
        read_testcases('.', [])
        mock_listdir.assert_called_once_with('.')

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access')
    def test_calls_access(self, mock_access):
        with self.assertRaises(RuntimeError):
            mock_access.return_value = False
            read_testcases('.', [])
            mock_access.assert_called_once_with()

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access')
    def test_throws_exception_if_cannot_access(self, mock_access):
        with self.assertRaises(RuntimeError):
            mock_access.return_value = False
            read_testcases('.', [])
            mock_access.assert_called_once_with()

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access', lambda _1, _2: True)
    @mock.patch('os.stat')
    def test_calls_stat(self, mock_stat):
        mock_stat.return_value = mock.Mock(st_size=0, st_mode=0)
        read_testcases('.', [])
        mock_stat.assert_called_once_with(None)

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access', lambda _1, _2: True)
    @mock.patch('os.stat', mock.Mock())
    @mock.patch('stat.S_ISREG')
    def test_doesnt_add_if_not_isreg(self, mock_isreg):
        q = []
        mock_isreg.return_value = False
        read_testcases('.', q)
        self.assertEqual(len(q), 0)

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access', lambda _1, _2: True)
    @mock.patch('stat.S_ISREG', mock.Mock())
    @mock.patch('os.stat')
    def test_doesnt_add_if_empty(self, mock_stat):
        q = []
        mock_stat.return_value = mock.Mock(st_size=0)
        read_testcases('.', q)
        self.assertEqual(len(q), 0)

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access', lambda _1, _2: True)
    @mock.patch('stat.S_ISREG', mock.Mock())
    @mock.patch('os.stat')
    def test_adds_to_queue(self, mock_stat):
        q = []
        mock_stat.return_value = mock.Mock(st_size=1)
        read_testcases('.', q)
        self.assertEqual(len(q), 1)

    @mock.patch('os.listdir', lambda _: [None])
    @mock.patch('os.access', lambda _1, _2: True)
    @mock.patch('stat.S_ISREG', mock.Mock())
    @mock.patch('os.stat')
    def test_throws_exception_if_too_big(self, mock_stat):
        mock_stat.return_value = mock.Mock(st_size=MAX_FILESIZE + 1)
        with self.assertRaises(RuntimeError):
            read_testcases('.', [])


#############################################################################
#                                                                           #
#                            <HERE_BE_DRAGONS>                              #
#                                                                           #
#############################################################################



def PFATAL(*args, **kwargs):
    raise NotImplementedError()


def set_itimer_real(tv_sec, tv_usec):
    # ITIMER_REAL This timer counts down in real (i.e., wall clock) timer.
    # At each expiration, a SIGALRM signal is generated.
    #
    # SIGALRM handler = handle_timeout, which sets child_timed_out and SIGKILLs child_pid.

    # static struct itimerval it
    # it.it_value.tv_sec = tv_sec
    # it.it_value.tv_usec = tv_usec
    # setitimer(ITIMER_REAL, &it, NULL)
    raise NotImplementedError()


def memset(where, value, length):
    raise NotImplementedError()


def run_target(mem_limit, argv, trace_bits, total_execs, child_pid, out_file,
               out_fd, child_timed_out, exec_tmout, kill_signal, stop_soon):
    """Execute target application, monitoring for timeouts. Return status
    information. The called program will update trace_bits[]."""

    child_timed_out[0] = True
    memset(trace_bits, 0, 65536)
    child_pid[0] = os.fork()

    if child_pid[0] < 0:
        PFATAL("fork() failed")

    if not child_pid[0]:
        memory_limit = mem_limit << 20
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        os.setsid()
        os.dup2(DEV_NULL, 1)
        os.dup2(DEV_NULL, 2)
        if out_file:
            os.dup2(DEV_NULL, 0)
        else:
            os.dup2(out_fd, 0)
            os.close(out_fd)

        os.close(DEV_NULL)
        os.execvp(argv[0], argv)
        sys.exit(EXEC_FAIL)

    set_itimer_real((exec_tmout / 1000), (exec_tmout % 1000) * 1000)

    waitpid_result, status = os.waitpid(child_pid[0], os.WUNTRACED)
    if waitpid_result <= 0:
        PFATAL("waitpid() failed")

    child_pid[0] = 0
    set_itimer_real(0, 0)
    total_execs[0] += 1

    # Report outcome to caller.

    if child_timed_out[0]:
        return FAULT_HANG

    if os.WIFSIGNALED(status) and not stop_soon:
        kill_signal[0] = os.WTERMSIG(status)
        return FAULT_CRASH

    return FAULT_ERROR if os.WEXITSTATUS(status) == EXEC_FAIL else 0


@mock.patch('__main__.memset', mock.Mock())
@mock.patch('__main__.set_itimer_real', mock.Mock())
@mock.patch('os.waitpid', mock.Mock(return_value=[1, 1]))
@mock.patch('os.setsid', mock.Mock())
@mock.patch('os.dup2', mock.Mock())
@mock.patch('os.close', mock.Mock())
@mock.patch('os.execvp', mock.Mock())
@mock.patch('sys.exit', mock.Mock())
class RunTargetTest(unittest.TestCase):

    def setUp(self):
        self.fork_patcher = mock.patch('os.fork', mock.Mock(return_value=1))
        self.fork_mocked = self.fork_patcher.start()
        self.total_execs = [0]
        self.child_pid = [0]
        self.child_timed_out = [False]
        self.kill_signal = [0]
        self.example_args = {
            'mem_limit': 1,
            'argv': ['something'],
            'trace_bits': '',  # FIXME
            'total_execs': self.total_execs,
            'child_pid': self.child_pid,
            'out_file': 'something',  # FIXME
            'out_fd': 255,
            'child_timed_out': self.child_timed_out,
            'exec_tmout': 0,
            'kill_signal': self.kill_signal,
            'stop_soon': False,
        }

    def tearDown(self):
        self.fork_patcher.stop()

    def test_calls_fork(self):
        run_target(**self.example_args)
        self.fork_mocked.assert_called_once_with()

    def test_doesnt_crash_in_forked_process(self):
        self.fork_mocked.return_value = 0
        run_target(**self.example_args)


#############################################################################
#                                                                           #
#                            </HERE_BE_DRAGONS>                             #
#                                                                           #
#############################################################################


if __name__ == '__main__':
    unittest.main()
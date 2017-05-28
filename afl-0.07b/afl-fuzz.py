#!/usr/bin/env python3

import collections
import ctypes
import os
import resource
import signal
import time
import stat
import sys
import unittest
import warnings

try:
    from unittest import mock
except ImportError:
    import mock

MAX_FILESIZE = 1 * 1000 * 1000
FAULT_NONE, FAULT_HANG, FAULT_CRASH, FAULT_ERROR = range(4)
EXEC_FAIL = 0x55
IPC_PRIVATE, IPC_CREAT, IPC_EXCL = 0, 512, 1024
SHM_ENV_VAR = "__AFL_SHM_ID"
CAL_CYCLES = 4


QueueEntry = collections.namedtuple('QueueEntry', ['fname'])


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


def has_new_bits(current, virgin, size):
    for i in range(size):
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

    os.environ[SHM_ENV_VAR] = str(shm_id)

    return shm_id, trace_bits


class HasNewBitsTest(unittest.TestCase):
    def test_returns_false_if_current_is_zero(self):
        self.assertFalse(has_new_bits(bytearray([0]), bytearray([1]), 1))

    def test_returns_true_is_have_common_bits(self):
        self.assertTrue(has_new_bits(bytearray([2]), bytearray([3]), 1))

    def test_updates_virgin_bits_if_common_bits(self):
        virgin = bytearray([3])
        has_new_bits(bytearray([2]), virgin, 1)
        self.assertEqual(virgin[0], 2)

    def test_updates_virgin_bits_if_common_bits_and_virgin_is_ctypes_buf(self):
        virgin = ctypes.create_string_buffer(1)
        virgin[0] = b'\x03'
        has_new_bits(bytearray([2]), virgin, 1)
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
        expected_args = (0, 1, IPC_CREAT | IPC_EXCL | 0o600)
        self.mock_shmget.assert_called_once_with(*expected_args)

    def test_calls_shmat(self):
        setup_shm(1)
        self.mock_shmat.assert_called_once_with(0, 0, 0)

    def test_assigns_env_variable(self):
        with mock.patch.dict(os.environ, {SHM_ENV_VAR: 'nope'}):
            setup_shm(1)
            self.assertNotEqual(os.environ[SHM_ENV_VAR], 'nope')


def read_testcases(in_dir, queue):
    """Read all testcases from the input directory, then queue them for
    testing."""
    for fname in os.listdir(in_dir):
        if not os.access(fname, os.R_OK):
            raise RuntimeError('Unable to open %s' % repr(fname))
        st = os.stat(fname)
        if not stat.S_ISREG(st.st_mode) or not st.st_size:
            continue
        if st.st_size > MAX_FILESIZE:
            raise RuntimeError('Test case %s is too big' % repr(fname))
        queue.append({'fname': fname, 'flen': st.st_size,
                      'keep': True, 'det_done': False})
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


def PFATAL(*_, **__):
    raise NotImplementedError()


def run_target_forked(mem_limit, out_fd, out_file, argv):
    if sys.version.startswith('3'):
        warnings.simplefilter("ignore", ResourceWarning)
    f = open(os.devnull)
    DEV_NULL = f.fileno()
    memory_limit = mem_limit << 20
    resource.setrlimit(resource.RLIMIT_AS, (memory_limit,
                       memory_limit))
    # NOTE: the following three instructions will not work unless we actually
    # fork and will silence all tracebacks. This might complicate debugging.
    os.setsid()
    os.dup2(DEV_NULL, 1)
    os.dup2(DEV_NULL, 2)
    if out_file:
        os.dup2(DEV_NULL, 0)
    else:
        os.dup2(out_fd, 0)
        os.close(out_fd)

    os.close(DEV_NULL)
    try:
        os.execvp(argv[0], argv)
    finally:
        os._exit(EXEC_FAIL)


@mock.patch('os.setsid', mock.Mock())
@mock.patch('os.dup2', mock.Mock())
@mock.patch('os.close', mock.Mock())
@mock.patch('os.execvp', mock.Mock())
@mock.patch('os._exit', mock.Mock())
@mock.patch('resource.setrlimit', mock.Mock())
# FIXME: nosetests doesn't like the following:
@mock.patch.object(globals()['__builtins__'], 'open',
                   lambda *_, **__: mock.Mock(fileno=lambda *_, **__: 9))
class RunTargetForkedTest(unittest.TestCase):

    def test_sets_rlimit(self):
        expected = (resource.RLIMIT_AS, (100 << 20, 100 << 20))
        with mock.patch('resource.setrlimit', mock.Mock()) as mock_rlimit:
            run_target_forked(100, 255, None, ['./a.out'])
            mock_rlimit.assert_called_once_with(*expected)

    def test_calls_setsid(self):
        with mock.patch('os.setsid', mock.Mock()) as mock_setsid:
            run_target_forked(100, 255, None, ['./a.out'])
            mock_setsid.assert_called_once_with()

    def test_duplicates_stdout(self):
        with mock.patch('os.dup2', mock.Mock()) as mock_dup2:
            run_target_forked(100, 255, None, ['./a.out'])
            self.assertIn(mock.call(9, 1), mock_dup2.call_args_list)

    def test_duplicates_stderr(self):
        with mock.patch('os.dup2', mock.Mock()) as mock_dup2:
            run_target_forked(100, 255, None, ['./a.out'])
            self.assertIn(mock.call(9, 2), mock_dup2.call_args_list)

    def test_duplicates_stdin_if_out_file(self):
        with mock.patch('os.dup2', mock.Mock()) as mock_dup2:
            run_target_forked(100, 255, True, ['./a.out'])
            self.assertIn(mock.call(9, 0), mock_dup2.call_args_list)

    def test_duplicates_out_fd_if_no_file(self):
        with mock.patch('os.dup2', mock.Mock()) as mock_dup2:
            run_target_forked(100, 255, None, ['./a.out'])
            self.assertIn(mock.call(255, 0), mock_dup2.call_args_list)

    def test_closes_out_fd_if_no_file(self):
        with mock.patch('os.close', mock.Mock()) as mock_close:
            run_target_forked(100, 255, None, ['./a.out'])
            self.assertIn(mock.call(255), mock_close.call_args_list)

    def test_closes_dev_null(self):
        with mock.patch('os.close', mock.Mock()) as mock_close:
            run_target_forked(100, 255, None, ['./a.out'])
            self.assertIn(mock.call(9), mock_close.call_args_list)

    def test_calls_execvp(self):
        with mock.patch('os.execvp', mock.Mock()) as mock_execvp:
            argv = ['./a.out', 'arg2']
            run_target_forked(100, 255, None, argv)
            mock_execvp.assert_called_once_with('./a.out', argv)

    def test_call_exit_after_execvp(self):
        with mock.patch('os._exit', mock.Mock()) as mock_exit:
            run_target_forked(100, 255, None, ['./a.out'])
            mock_exit.assert_called_once_with(EXEC_FAIL)


def run_target(mem_limit, argv, trace_bits, total_execs, child_pid, out_file,
               out_fd, child_timed_out, exec_tmout, kill_signal, stop_soon):
    """Execute target application, monitoring for timeouts. Return status
    information. The called program will update trace_bits[]."""

    child_timed_out[0] = False
    ctypes.memset(trace_bits, 0, 65536)
    child_pid[0] = os.fork()

    # TODO: can we actually get there? Perhaps it's enough to let it raise
    # an exception?
    if child_pid[0] < 0:
        PFATAL("fork() failed")

    if not child_pid[0]:
        run_target_forked(mem_limit, out_fd, out_file, argv)
    exec_tmout_seconds = exec_tmout / 1000.0 + ((exec_tmout % 1000) / 1000000)
    signal.setitimer(signal.ITIMER_REAL, exec_tmout_seconds)

    # FIXME: this part doesn't work under Python < 3.5 because of lack of
    # proper EINTR handling. Needs a reimplementation for compatibility.
    waitpid_result, status = os.waitpid(child_pid[0], os.WUNTRACED)
    if waitpid_result <= 0:
        # TODO: can we actually get there? Perhaps it's enough to let it raise
        # an exception?
        PFATAL("waitpid() failed")

    child_pid[0] = 0
    signal.setitimer(signal.ITIMER_REAL, 0.0)
    total_execs[0] += 1

    # Report outcome to caller.

    if child_timed_out[0]:
        return FAULT_HANG

    if os.WIFSIGNALED(status) and not stop_soon[0]:
        kill_signal[0] = os.WTERMSIG(status)
        return FAULT_CRASH

    return FAULT_ERROR if os.WEXITSTATUS(status) == EXEC_FAIL else FAULT_NONE


@mock.patch('ctypes.memset', mock.Mock())
@mock.patch('signal.setitimer', mock.Mock())
@mock.patch('os.waitpid', mock.Mock(return_value=[1, 'status']))
@mock.patch('os.fork', mock.Mock(return_value=1))
@mock.patch('os.WIFSIGNALED', mock.Mock(return_value=1))
@mock.patch('os.WEXITSTATUS', mock.Mock(return_value=EXEC_FAIL))
@mock.patch('os.WTERMSIG', mock.Mock(return_value=11))
@mock.patch.dict(globals(), {'run_target_forked': mock.Mock()})
class RunTargetTest(unittest.TestCase):

    def setUp(self):
        self.example_args = {
            'mem_limit': 100,
            'argv': ['something'],
            'trace_bits': '',
            'total_execs': [0],
            'child_pid': [0],
            'out_file': 'something',
            'out_fd': 255,
            'child_timed_out': [True],
            'exec_tmout': 200,
            'kill_signal': [0],
            'stop_soon': [False],
        }

    def test_calls_fork(self):
        with mock.patch('os.fork', mock.Mock(return_value=1)) as fork_mocked:
            run_target(**self.example_args)
            fork_mocked.assert_called_once_with()

    def test_doesnt_crash_in_forked_process(self):
        with mock.patch('os.fork', mock.Mock(return_value=0)):
            run_target(**self.example_args)

    def test_resets_child_timed_out(self):
        child_timed_out = [True]
        self.example_args['child_timed_out'] = child_timed_out
        run_target(**self.example_args)
        self.assertFalse(child_timed_out[0])

    def test_runs_pfatal_if_fork_failed(self):
        mock_pfatal = mock.Mock()
        with mock.patch('os.fork', mock.Mock(return_value=-1)):
            with mock.patch.dict(globals(), {'PFATAL': mock_pfatal}):
                run_target(**self.example_args)
                mock_pfatal.assert_called_once_with('fork() failed')

    def test_resets_trace_bits(self):
        self.example_args['trace_bits'] = 'hello there'
        with mock.patch('ctypes.memset') as mock_ctypes:
            run_target(**self.example_args)
            mock_ctypes.assert_called_once_with('hello there', 0, 65536)

    def test_sets_timer_then_resets_it(self):
        first_timer_secs = 0.20020000000000002
        with mock.patch('signal.setitimer') as mock_setitimer:
            run_target(**self.example_args)
            self.assertEqual([mock.call(signal.ITIMER_REAL, first_timer_secs),
                              mock.call(signal.ITIMER_REAL, 0.0)],
                             mock_setitimer.call_args_list)

    def test_calls_waitpid(self):
        mock_waitpid = mock.Mock(return_value=[1, 'status'])
        with mock.patch('os.waitpid', mock_waitpid):
            run_target(**self.example_args)
            mock_waitpid.assert_called_once_with(1, os.WUNTRACED)

    def test_calls_WIFSIGNALED(self):
        with mock.patch('os.WIFSIGNALED') as mock_wifsignaled:
            run_target(**self.example_args)
            mock_wifsignaled.assert_called_once_with('status')

    def test_sets_kill_signal_if_wifsignaled_and_not_stop_soon(self):
        kill_signal = [0]
        self.example_args['kill_signal'] = kill_signal
        run_target(**self.example_args)
        self.assertEqual(kill_signal[0], 11)

    def test_doesnt_set_kill_signal_if_not_stop_soon(self):
        with mock.patch('os.WTERMSIG', mock.Mock(return_value=0)):
            kill_signal = [0]
            self.example_args['kill_signal'] = kill_signal
            run_target(**self.example_args)
            self.assertEqual(kill_signal[0], 0)

    def test_doesnt_set_kill_signal_if_not_wifsignaled(self):
        with mock.patch('os.WTERMSIG', mock.Mock(return_value=0)):
            kill_signal = [0]
            self.example_args['kill_signal'] = kill_signal
            run_target(**self.example_args)
            self.assertEqual(kill_signal[0], 0)

    def test_returns_fault_hang_if_timed_out(self):
        class always_true(list):
            def __getitem__(*_, **__):
                return True
        self.example_args['child_timed_out'] = always_true([True])
        self.assertEqual(run_target(**self.example_args), FAULT_HANG)

    def test_returns_fault_crash_if_appropriate(self):
        self.assertEqual(run_target(**self.example_args), FAULT_CRASH)

    def test_returns_fault_error_if_appropriate(self):
        with mock.patch('os.WIFSIGNALED', mock.Mock(return_value=0)):
            self.assertEqual(run_target(**self.example_args), FAULT_ERROR)

    def test_returns_fault_none_if_appropriate(self):
        with mock.patch('os.WIFSIGNALED', mock.Mock(return_value=0)):
            with mock.patch('os.WEXITSTATUS', mock.Mock(return_value=0)):
                self.assertEqual(run_target(**self.example_args), FAULT_NONE)


# RUN_TARGET_FORKED() will behave as previously, with a 1s slowdown
# that should trigger SIGALRM
OLD_RUN_TARGET_FORKED = run_target_forked


def MOCK_RUN_TARGET_FORKED_FN(*args, **kwargs):
    time.sleep(1)
    OLD_RUN_TARGET_FORKED(*args, **kwargs)


MOCK_RUN_TARGET_FORKED = mock.Mock(side_effect=MOCK_RUN_TARGET_FORKED_FN)


class SHMSystemTests(unittest.TestCase):

    def setUp(self):
        self.shmctl = ctypes.cdll.LoadLibrary("libc.so.6").shmctl
        self.shm_id, self.trace_bits = setup_shm(65536)
        self.run_target_args = {
            'mem_limit': 100,
            'argv': ['something'],
            'trace_bits': self.trace_bits,
            'total_execs': [0],
            'child_pid': [0],
            'out_file': 'something',  # FIXME
            'out_fd': 255,
            'child_timed_out': [False],
            'exec_tmout': 100,
            'kill_signal': [0],
            'stop_soon': [False],
        }

    def tearDown(self):
        self.shmctl(self.shm_id, 0, 0)

    def test_count_bits_1(self):
        self.trace_bits[1] = to_byte(0x01)
        self.assertEqual(count_bits(self.trace_bits), 1)

    def test_count_bits_2(self):
        self.trace_bits[0] = to_byte(0x03)
        self.assertEqual(count_bits(self.trace_bits), 2)

    def test_count_bits_4095(self):
        self.trace_bits[4095] = to_byte(0xFF)
        self.assertEqual(count_bits(self.trace_bits), 8)

    def test_count_bits_65536(self):
        with self.assertRaises(IndexError):
            self.trace_bits[65536] = to_byte(0xFF)
            self.assertEqual(count_bits(self.trace_bits), 8)

    def test_count_bits_and_memset(self):
        self.trace_bits[0] = to_byte(0xFF)
        self.trace_bits[4095] = to_byte(0xFF)
        ctypes.memset(self.trace_bits, 0, 65536)
        self.assertEqual(count_bits(self.trace_bits), 0)

    def test_exercise_has_new_bits(self):
        # TODO
        pass

    def test_run_target_nonexistent_binary(self):
        retcode = run_target(**self.run_target_args)
        self.assertEqual(retcode, FAULT_ERROR)

    @mock.patch.dict(globals(), {'run_target_forked': MOCK_RUN_TARGET_FORKED})
    def test_run_target_timeout(self):
        # save SIGALRM signal handler so that we can restore it if anything
        # fails
        old_signal_handler = signal.getsignal(signal.SIGALRM)

        def sigalrm_handler(*_, **__):
            child_timed_out[0] = True
            if child_pid[0] > 0:
                os.kill(child_pid[0], signal.SIGKILL)
        signal.signal(signal.SIGALRM, sigalrm_handler)

        try:
            child_timed_out = [False]
            child_pid = [0]
            kill_signal = [0]
            self.run_target_args.update({
                'child_pid': child_pid,
                'kill_signal': kill_signal,
                'child_timed_out': child_timed_out,
            })
            retcode = run_target(**self.run_target_args)
            self.assertEqual(retcode, FAULT_HANG)
        finally:
            signal.signal(signal.SIGALRM, old_signal_handler)

    def test_run_target_no_error(self):
        self.run_target_args['argv'] = ['./a.out']
        retcode = run_target(**self.run_target_args)
        self.assertEqual(retcode, FAULT_NONE)
        self.assertNotEqual(bytearray(self.trace_bits),
                            b'\x00' * len(self.trace_bits))

    def test_run_target_crash(self):
        def kill_self(*_, **__):
            os.kill(os.getpid(), signal.SIGKILL)

        with mock.patch.dict(globals(), {'run_target_forked': kill_self}):
            retcode = run_target(**self.run_target_args)
            self.assertEqual(retcode, FAULT_CRASH)


class ReadTestcasesSystemTests(unittest.TestCase):
    pass


def FATAL(*_, **__):
    raise NotImplementedError()


def OKF(*_, **__):
    raise NotImplementedError()


def ACTF(*_, **__):
    raise NotImplementedError()


def perform_dry_run(queue, dumb_mode, mem_limit, argv, trace_bits, total_execs,
                    child_pid, out_file, out_fd, child_timed_out, exec_tmout,
                    kill_signal, stop_soon, virgin_bits):

    for q in queue:

        ACTF("Verifying test case '%s'...", q.fname)

        if not out_file:
            out_f = open(q.fname, 'r')
            out_fd = out_f.fileno()
        else:
            try:
                os.unlink(out_file)
            except FileNotFoundError:
                pass
            if os.link(q.fname, out_file):
                PFATAL("link() failed")

        fault = run_target(mem_limit, argv, trace_bits, total_execs, child_pid,
                           out_file, out_fd, child_timed_out, exec_tmout,
                           kill_signal, stop_soon)
        if stop_soon[0]:
            return

        if fault == FAULT_HANG:
            FATAL("Test case '%s' results in a hang (adjusting -t "
                  "may help)", q.fname)
        elif fault == FAULT_CRASH:
            FATAL("Test case '%s' results in a crash", q.fname)
        elif fault == FAULT_ERROR:
            FATAL("Unable to execute target application ('%s')", argv[0])

        if not has_new_bits(trace_bits, virgin_bits, 65536) and not dumb_mode:
            FATAL("No instrumentation detected (you can always try -n)")

        # Wait long enough for any time(0)-based randomness to change.

        for i in range(15):
            if stop_soon[0]:
                break
            time.sleep(0.1)
        if stop_soon[0]:
            return

        for i in range(CAL_CYCLES):

            if not out_file:
                out_f.seek(0)
            fault = run_target(mem_limit, argv, trace_bits, total_execs,
                               child_pid, out_file, out_fd, child_timed_out,
                               exec_tmout)

            if stop_soon[0]:
                return

            if fault == FAULT_HANG:
                FATAL("Test case '%s' results in intermittent hangs "
                      "(adjusting -t may help)", q.fname)
            elif fault == FAULT_CRASH:
                FATAL("Test case '%s' results in intermittent "
                      "crashes", q.fname)
            elif fault == FAULT_ERROR:
                FATAL("Unable to execute target application (huh)")

            if has_new_bits(trace_bits, virgin_bits, 65536):
                FATAL("Inconsistent instrumentation output for test case '%s'",
                      q.fname)

        if not out_file:
            out_f.close()

        OKF("Done: %u bits set, %u remaining in the bitmap.\n",
            count_bits(trace_bits), count_bits(virgin_bits))


@mock.patch.dict(globals(), {'ACTF': mock.Mock()})
class PerformDryRunSystemTests(unittest.TestCase):

    def setUp(self):
        self.shm_id, self.trace_bits = setup_shm(65536)
        self.virgin_bits = ctypes.create_string_buffer(65536)
        ctypes.memset(self.virgin_bits, 0, 65536)
        self.example_args = {
            'mem_limit': 100,
            'argv': ['./a.out'],
            'trace_bits': self.trace_bits,
            'total_execs': [0],
            'child_pid': [0],
            'out_file': '',
            'out_fd': 255,
            'child_timed_out': [False],
            'exec_tmout': 100,
            'kill_signal': [0],
            'stop_soon': [False],
            'virgin_bits': self.virgin_bits,
            'queue': [QueueEntry(fname='/dev/null')],
            'dumb_mode': False,
        }

    def tearDown(self):
        ctypes.cdll.LoadLibrary("libc.so.6").shmctl(self.shm_id)

    def test_doesnt_crash(self):
        perform_dry_run(**self.example_args)


if __name__ == '__main__':
    # run_target_forked(1, open('/etc/fstab').fileno(), None, ['./a.out'])
    unittest.main()

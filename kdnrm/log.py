import logging
import traceback
import sys
import enum


class Log:

    _name = "kdnrm"
    _logger = None

    def __init__(self, **kwargs):

        Log._logger = logging.getLogger(Log._name)

        for handler in Log._logger.handlers[:]:
            Log._logger.removeHandler(handler)
        handler = logging.StreamHandler()
        Log._logger.addHandler(handler)

        # Try to match what the gateway sets. We include the thread id.
        formatter = logging.Formatter(f'%(asctime)s %(name)s  %(levelname)s: %(message)s')
        handler.setFormatter(formatter)

        level = kwargs.get("level")
        if level is not None:
            Log.set_log_level(level)

    @staticmethod
    def init(**kwargs):
        Log(**kwargs)
        return Log

    @staticmethod
    def set_log_level(level):
        if level is None:
            level = logging.WARNING
        if isinstance(level, str) is True:
            level = getattr(logging, level)
        Log._logger.setLevel(level)

    @staticmethod
    def add_secret(secret):
        pass

    @staticmethod
    def debug(msg, **kwargs):
        Log._logger.debug(msg, **kwargs)

    @staticmethod
    def info(msg, **kwargs):
        Log._logger.info(msg, **kwargs)

    @staticmethod
    def warning(msg, **kwargs):
        Log._logger.warning(msg, **kwargs)

    @staticmethod
    def warn(msg, **kwargs):
        Log._logger.warning(msg, **kwargs)

    @staticmethod
    def error(msg, **kwargs):
        Log._logger.error(msg, **kwargs)

    @staticmethod
    def critical(msg, **kwargs):
        Log._logger.critical(msg, **kwargs)

    @staticmethod
    def get_traceback(err=None):
        if err is not None:
            msg = ''.join(traceback.format_exception(None, err, err.__traceback__))
        else:
            exc = sys.exc_info()[0]
            # the last one would be full_stack()
            stack = traceback.extract_stack()[:-1]
            if exc is not None:  # i.e., an exception is present
                del stack[-1]  # remove call of full_stack, the printed exception
                # will contain the caught exception caller instead
            trc = 'Traceback (most recent call last):\n'
            msg = trc + ''.join(traceback.format_list(stack))
            if exc is not None:
                msg += '  ' + traceback.format_exc().lstrip(trc)
        return msg

    @staticmethod
    def traceback(err=None, **kwargs):
        msg = Log.get_traceback(err)
        Log.info(msg, **kwargs)
        return msg


class LogLevel(enum.Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

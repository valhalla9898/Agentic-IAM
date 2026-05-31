import sys
import logging
import types

from utils.logger import (
    setup_logging,
    get_logger,
    SecurityLogFilter,
    StructuredLogger,
    AuditLogHandler,
    LoggerMixin,
    log_function_call,
    log_performance,
)


def test_setup_and_get_logger():
    logger = setup_logging(log_level='DEBUG', enable_console=False)
    assert isinstance(logger, logging.Logger)
    named = get_logger('testmod')
    assert isinstance(named, logging.Logger)


def test_security_filter_masks():
    f = SecurityLogFilter()
    record = logging.LogRecord('n', logging.INFO, '/', 1, 'my password is 123', (), None)
    assert f.filter(record)
    assert record.msg == '[REDACTED - SENSITIVE INFORMATION]'


def test_structured_logger_and_mixin(caplog):
    logger = setup_logging(log_level='INFO', enable_console=False)
    s = StructuredLogger(logger)
    s.info('info', user='u1')
    s.warning('warn', stage='s')
    # LoggerMixin usage

    class C(LoggerMixin):
        pass

    c = C()
    c.log_info('ci', x=1)
    c.log_warning('cw', y=2)
    c.log_error('ce', z=3)


def test_decorators_behavior():
    @log_function_call
    @log_performance
    def f(a, b):
        return a + b

    assert f(1, 2) == 3

    @log_function_call
    def fail():
        raise ValueError('boom')

    try:
        fail()
    except ValueError:
        pass


def test_audit_log_handler_invokes_audit_manager(monkeypatch):
    # Create fake audit_compliance module
    fake = types.SimpleNamespace()
    class AE:
        SYSTEM_STARTUP = 'system_startup'

    class ES:
        LOW = 'low'
        MEDIUM = 'medium'
        HIGH = 'high'
        CRITICAL = 'critical'

    fake.AuditEventType = AE
    fake.EventSeverity = ES
    sys.modules['audit_compliance'] = fake

    calls = {}

    class DummyAuditManager:
        def log_event(self, **kwargs):
            calls['called'] = True

    handler = AuditLogHandler(audit_manager=DummyAuditManager())
    record = logging.LogRecord('n', logging.INFO, '/', 1, 'hello', (), None)
    handler.emit(record)
    assert calls.get('called') is True

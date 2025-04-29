from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _

class ApiScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api_scanner'
    verbose_name = _('API Security Scanner')

    def ready(self):
        # Import signals module only after apps are ready
        try:
            import api_scanner.signals  # noqa: F401
            from .signals import setup_signals
            setup_signals()
        except ImportError:
            # Log this error in production
            pass
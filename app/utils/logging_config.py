# app/utils/logging_config.py
import logging
import os
import json
from logging.handlers import RotatingFileHandler

class JsonFormatter(logging.Formatter):
    def format(self, record):
        base = {
            "level": record.levelname,
            "msg": record.getMessage(),
            "logger": record.name,
            "time": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
        }
        # Extras serialisables
        for key, val in record.__dict__.items():
            if key not in (
                "msg","args","levelname","levelno","pathname","filename","module",
                "exc_info","exc_text","stack_info","lineno","funcName","created",
                "msecs","relativeCreated","thread","threadName","processName","process"
            ):
                try:
                    json.dumps({key: val})
                    base[key] = val
                except Exception:
                    pass
        return json.dumps(base, ensure_ascii=False)

def setup_logging(app):
    log_path = app.config.get("LOG_FILE", os.path.join(app.config.get("LOG_DIR", "logs"), "app.log"))
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    level_name = (app.config.get("LOG_LEVEL") or "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    # Handler app
    app_handler = RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
    app_handler.setFormatter(JsonFormatter())
    app_handler.setLevel(level)

    # Root/app logger
    app.logger.handlers.clear()
    app.logger.setLevel(level)
    app.logger.addHandler(app_handler)

    # Logger admin_actions indépendant
    admin_path = os.path.join(app.config.get("LOG_DIR", "logs"), "admin_actions.log")
    admin_handler = RotatingFileHandler(admin_path, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8")
    admin_handler.setFormatter(JsonFormatter())
    admin_handler.setLevel(level)

    admin_logger = logging.getLogger("admin_logger")
    admin_logger.handlers.clear()
    admin_logger.setLevel(level)
    admin_logger.addHandler(admin_handler)

    app.logger.info("[BOOT] Logging configuré (rotation + JSON)")

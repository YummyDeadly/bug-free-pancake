import os
import logging
from datetime import datetime

class LogService:

    LOG_DIR = "logs"

    @staticmethod
    def setup_logging():
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        log_filename = f"app_{timestamp}.log"
        os.makedirs(LogService.LOG_DIR, exist_ok=True)
        logging.basicConfig(
            filename=os.path.join(LogService.LOG_DIR, log_filename),
            level=logging.INFO,
            format="%(asctime)s - [%(levelname)s] - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )

    @staticmethod
    def create_action_log(message):
        logging.info(message)

    @staticmethod
    def create_error_log(error):
        logging.error(error)
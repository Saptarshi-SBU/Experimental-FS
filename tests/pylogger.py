import logging
import logging.config

loggers = dict()

def GetPyLogger(name,
                log_file, \
                level=logging.DEBUG, \
                maxSize=50 * 1024 * 1024, \
                maxCount=2):
    """
    Rotating Log

    Note : Multiple logger instances (same name) results in duplicate logs
    """
    global loggers

    if name in loggers:
        return loggers[name]
    else:
        logger = logging.getLogger(name)
        logger.setLevel(level)
        formatter = logging.Formatter("%(asctime)s %(levelname)s" \
                " %(threadName)s [%(process)d] %(message)s")
        fileHandler = logging.handlers.RotatingFileHandler(log_file, mode='a', \
                maxBytes=maxSize, backupCount=maxCount)
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
        loggers[name] = logger
        return logger

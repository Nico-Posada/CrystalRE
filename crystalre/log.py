import logging

# TODO: make the level an option users can set...
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("CrystalRE")
logger.propagate = False

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(
    "[{name} {levelname[0]}] {message}",
    style="{"
))
logger.addHandler(handler)

def log(msg: str) -> None:
    info(msg)

def info(msg: str) -> None:
    logger.info(msg)

def warning(msg: str) -> None:
    logger.warning(msg)

def error(msg: str) -> None:
    logger.error(msg)

def debug(msg: str) -> None:
    logger.debug(msg)

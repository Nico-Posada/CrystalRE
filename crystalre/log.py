import ida_kernwin

def log(msg: str) -> None:
    ida_kernwin.msg(f"[CrystalRE] {msg}\n")

def info(msg: str) -> None:
    log(msg)

def warning(msg: str) -> None:
    ida_kernwin.msg(f"[CrystalRE w] {msg}\n")

def error(msg: str) -> None:
    ida_kernwin.msg(f"[CrystalRE e] {msg}\n")

def debug(msg: str) -> None:
    ida_kernwin.msg(f"[CrystalRE d] {msg}\n")

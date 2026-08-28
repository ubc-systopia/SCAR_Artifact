# Single-step V8 builtin instructions under gdb, stepping over C++ helpers.
#
#   (gdb) source gdb_step_builtins.py
#   (gdb) sib                  # until a breakpoint or program exit
#   (gdb) sib 5000             # at most 5000 instructions
#   (gdb) sib trace.log        # write the trace to a file
#   (gdb) sib 5000 trace.log   # both

import gdb


_bp_hit = {"flag": False}


def _on_stop(event):
    if isinstance(event, gdb.BreakpointEvent):
        _bp_hit["flag"] = True


def _exec(cmd):
    _bp_hit["flag"] = False
    gdb.execute(cmd, to_string=True)
    return _bp_hit["flag"]


def _alive():
    try:
        return len(gdb.selected_inferior().threads()) > 0
    except Exception:
        return False


def _pc_and_name():
    try:
        frame = gdb.newest_frame()
    except gdb.error:
        return None, None
    return frame.pc(), frame.name()


def _is_builtin(name):
    return name is not None and name.startswith("Builtins_")


_sym_base = {}


def _sym_offset(pc, name):
    if name is None:
        return None
    base = _sym_base.get(name)
    if base is None:
        base = -1
        try:
            info = gdb.execute("info symbol 0x%x" % pc, to_string=True).strip()
        except gdb.error:
            info = ""
        rest = info[len(name):].lstrip() if info.startswith(name) else None
        if rest is not None and (not rest or rest[0] in "+ "):
            if not rest.startswith("+"):
                base = pc
            else:
                try:
                    base = pc - int(rest[1:].strip().split()[0], 0)
                except (ValueError, IndexError):
                    base = -1
        _sym_base[name] = base
    return None if base < 0 else pc - base


def _format_trace_line(pc, name):
    label = name if name else "??"
    offset = _sym_offset(pc, name)
    if offset is not None:
        label = "%s+0x%x" % (label, offset)
    return "0x%016x  %s\n" % (pc, label)


class StepInBuiltins(gdb.Command):

    def __init__(self):
        super(StepInBuiltins, self).__init__("sib", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        limit = None
        path = None
        for tok in arg.split():
            if tok.isdigit():
                limit = int(tok)
            else:
                path = tok

        out = open(path, "w") if path else None
        gdb.events.stop.connect(_on_stop)
        logged = 0
        reason = "step cap reached"
        try:
            while limit is None or logged < limit:
                status = self._one_step(out)
                if status == "step":
                    logged += 1
                    continue
                reason = status
                break
        except KeyboardInterrupt:
            reason = "interrupted"
        finally:
            gdb.events.stop.disconnect(_on_stop)
            if out:
                out.close()
        print(
            "[sib] %s; logged %d builtin instructions -> %s"
            % (reason, logged, path if path else "gdb stdout")
        )

    def _emit(self, out, pc, name):
        line = _format_trace_line(pc, name)
        if out:
            out.write(line)
            out.flush()
        else:
            gdb.write(line)
            gdb.flush()

    def _one_step(self, out):
        try:
            hit = _exec("si")
        except gdb.error as e:
            return "error: %s" % e
        if not _alive():
            return "program exited"
        if hit:
            pc, name = _pc_and_name()
            if _is_builtin(name):
                self._emit(out, pc, name)
            return "stopped at breakpoint"

        guard = 0
        while True:
            pc, name = _pc_and_name()
            if _is_builtin(name):
                break
            guard += 1
            if guard > 200000:
                return "stuck outside builtins at %s" % name
            try:
                hit = _exec("finish")
            except gdb.error:
                try:
                    hit = _exec("si")
                except gdb.error as e:
                    return "error: %s" % e
            if not _alive():
                return "program exited"
            if hit:
                pc, name = _pc_and_name()
                if _is_builtin(name):
                    self._emit(out, pc, name)
                return "stopped at breakpoint"

        self._emit(out, pc, name)
        return "step"


StepInBuiltins()
print("[sib] loaded - use `sib`, `sib N`, `sib file`, or `sib N file`")
print("[sib] `sib <file>` writes a clean trace file; the file is never noisy.")
print("[sib] To silence the SHELL, paste these at the (gdb) prompt before sib:")
print("        set logging enabled off")
print("        set logging file /dev/null")
print("        set logging redirect on")
print("        set logging enabled on")
print("[sib] restore the console afterwards with:  set logging enabled off")


def _is_jit(name):
    return name is None


class StepInJIT(gdb.Command):

    def __init__(self):
        super(StepInJIT, self).__init__("sij", gdb.COMMAND_RUNNING)

    def invoke(self, arg, from_tty):
        limit = None
        path = None
        for tok in arg.split():
            if tok.isdigit():
                limit = int(tok)
            else:
                path = tok

        out = open(path, "w") if path else None
        gdb.events.stop.connect(_on_stop)
        logged = 0
        reason = "step cap reached"
        try:
            while limit is None or logged < limit:
                status = self._one_step(out)
                if status == "step":
                    logged += 1
                    continue
                reason = status
                break
        except KeyboardInterrupt:
            reason = "interrupted"
        finally:
            gdb.events.stop.disconnect(_on_stop)
            if out:
                out.close()
        print(
            "[sij] %s; logged %d JIT instructions -> %s"
            % (reason, logged, path if path else "gdb stdout")
        )

    def _emit(self, out, pc):
        line = "0x%016x  ??\n" % pc
        if out:
            out.write(line)
            out.flush()
        else:
            gdb.write(line)
            gdb.flush()

    def _one_step(self, out):
        try:
            hit = _exec("si")
        except gdb.error as e:
            return "error: %s" % e
        if not _alive():
            return "program exited"
        if hit:
            pc, name = _pc_and_name()
            if _is_jit(name):
                self._emit(out, pc)
            return "stopped at breakpoint"

        guard = 0
        while True:
            pc, name = _pc_and_name()
            if _is_jit(name):
                break
            guard += 1
            if guard > 200000:
                return "stuck outside JIT at %s" % name
            try:
                hit = _exec("finish")
            except gdb.error:
                try:
                    hit = _exec("si")
                except gdb.error as e:
                    return "error: %s" % e
            if not _alive():
                return "program exited"
            if hit:
                pc, name = _pc_and_name()
                if _is_jit(name):
                    self._emit(out, pc)
                return "stopped at breakpoint"

        self._emit(out, pc)
        return "step"


StepInJIT()
print("[sij] loaded - use `sij`, `sij N`, `sij file`, or `sij N file`")
print("[sij] records only anonymous JIT instructions (?? ()), skipping builtins/v8::internal.")

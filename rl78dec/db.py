"""
Database-backed persistence layer for rl78dec using IDA netnodes.

Stores and retrieves per-function:
- Variable renames (old_name -> new_name)
- Variable type overrides (var_name -> type_str)
- Function prototype overrides (prototype string)
- Global UI preferences (sync with disassembly enabled)

When run outside IDA (headless tests), falls back to an in-memory dictionary.
"""

import json

try:
    import ida_netnode
except ImportError:
    ida_netnode = None

NODE_NAME = "$ rl78dec"
_MEM_STORAGE = {}
_MEM_SYNC = True


def _get_node():
    if ida_netnode is None:
        return None
    try:
        node = ida_netnode.netnode()
        node.create(NODE_NAME)
        return node
    except Exception:
        return None


def get_func_data(func_ea):
    """Retrieve persistent renames, types, and prototype for a function."""
    node = _get_node()
    if node is None:
        return _MEM_STORAGE.get(func_ea, {"renames": {}, "types": {}, "proto": None})
    try:
        val = node.supstr(func_ea)
        if val:
            return json.loads(val)
    except Exception:
        pass
    return {"renames": {}, "types": {}, "proto": None}


def set_func_data(func_ea, data):
    """Save persistent renames, types, and prototype for a function."""
    node = _get_node()
    if node is None:
        _MEM_STORAGE[func_ea] = data
        return
    try:
        node.supset(func_ea, json.dumps(data))
    except Exception:
        _MEM_STORAGE[func_ea] = data


def set_var_rename(func_ea, old_name, new_name):
    """Save a variable rename (e.g. v0 -> counter, or counter -> new_counter).
    
    If new_name is empty or None, the rename is cleared, reverting to default.
    """
    data = get_func_data(func_ea)
    renames = data.setdefault("renames", {})

    # If old_name was previously mapped from a canonical name, update that mapping
    canonical = None
    for k, v in renames.items():
        if v == old_name:
            canonical = k
            break
    key = canonical if canonical is not None else old_name

    if not new_name or new_name == key:
        renames.pop(key, None)
    else:
        renames[key] = new_name
    set_func_data(func_ea, data)


def set_var_type(func_ea, var_name, type_str):
    """Save a variable type override (e.g. v0 -> uint32_t *).
    
    If type_str is empty or None, the override is cleared.
    """
    data = get_func_data(func_ea)
    types = data.setdefault("types", {})
    if not type_str:
        types.pop(var_name, None)
    else:
        types[var_name] = type_str.strip()
    set_func_data(func_ea, data)


def set_func_proto(func_ea, proto_str):
    """Save a function prototype override (e.g. int sub_221D(uint16_t count)).
    
    If proto_str is empty or None, the override is cleared.
    """
    data = get_func_data(func_ea)
    if not proto_str:
        data["proto"] = None
    else:
        data["proto"] = proto_str.strip()
    set_func_data(func_ea, data)


def get_sync_enabled():
    """Check if 'Sync with Disassembly' is enabled (defaults to True)."""
    global _MEM_SYNC
    node = _get_node()
    if node is None:
        return _MEM_SYNC
    try:
        val = node.altval(0)
        return val != 2 # 2 means explicitly disabled; 0 or 1 means enabled
    except Exception:
        return _MEM_SYNC


def set_sync_enabled(enabled):
    """Persist the 'Sync with Disassembly' preference."""
    global _MEM_SYNC
    _MEM_SYNC = bool(enabled)
    node = _get_node()
    if node is not None:
        try:
            node.altset(0, 1 if enabled else 2)
        except Exception:
            pass


def clear_func_data(func_ea):
    """Clear all persistent customizations for a function."""
    node = _get_node()
    if node is None:
        _MEM_STORAGE.pop(func_ea, None)
        return
    try:
        node.supdel(func_ea)
    except Exception:
        pass

# Lua 5.1 compatibility

Rex scripts target Lua 5.1. This server runs Lua 5.4 (mlua). Scripts
and config files are written for that 5.1 surface, so the differences
below matter whenever script behavior diverges. The notes compare the
Lua 5.1 and 5.4 reference manuals with what this runtime actually
exposes. The shims live in `script.rs`
(`LUA51_COMPAT`, installed for both script runs and config files) and
are covered by `lua51_compat_shims_restore_the_51_surface`.

## Shimmed (5.1 names restored when 5.4 lacks them)

| 5.1 name | 5.4 situation | Shim |
| --- | --- | --- |
| `unpack` | moved to `table.unpack` | global alias |
| `loadstring` | renamed `load` | global alias |
| `math.pow` | removed (use `^`) | `x ^ y` |
| `math.atan2` | folded into two-arg `math.atan` | forwards |
| `math.log10` | `math.log(x, 10)` | forwards |
| `math.ldexp` | removed | `x * 2 ^ e` |
| `math.frexp` | removed | computed via `math.log` with boundary correction |
| `table.maxn` | removed | largest positive numeric key |
| `table.getn` | removed | `#t` |
| `string.gfind` | renamed `string.gmatch` | alias |
| `gcinfo` | `collectgarbage("count")` | forwards (KB, as in 5.1) |
| `package.loaders` | renamed `package.searchers` | alias |
| `setfenv` / `getfenv` | no function environments in 5.2+ | emulated over the function's `_ENV` upvalue via the debug library; both the function form and the stack-level form (levels counted from the caller, as in 5.1) |

## 5.4 additions (superset; harmless for compatibility)

Integers and integer arithmetic, `//`, bitwise operators, `goto` and
labels, `<const>` / `<close>` variables, the `utf8` library,
`string.pack` / `string.unpack`, `math.tointeger` / `math.type` /
`math.ult`, `coroutine.close`, `warn`. Scripts using them run here but
would fail on the official runtime; nothing to do server-side.

## Deltas deliberately not shimmed

- `tostring(3.0)` is `"3.0"` in 5.4, `"3"` in 5.1 (floats keep their
  mark). Number formatting in general uses the same `%.14g` for
  non-integral floats, so only integral floats differ. Rewriting the
  global `tostring` would also change numeric coercion inside the
  server's own Lua glue; scripts that format values should use
  `string.format("%d", ...)` or `math.tointeger` explicitly.
- `string.format("%d", 1.5)` errors in 5.4 ("bad argument"); 5.1
  silently truncated. Same remedy as above.
- `__pairs` / `__ipairs` metamethods are honored by `pairs` / `ipairs`
  in 5.4 and ignored in 5.1, so iteration over userdata-backed tables
  can differ where a flavor defines them. No shim; noted for script
  debugging.
- `module()` is not provided. The 5.1 module idiom has no 5.4
  equivalent; modules should return a table instead.
- The `setfenv` emulation only covers functions that have an `_ENV`
  upvalue (any function that touches globals). A function using no
  globals has no environment to replace and the shim leaves it alone,
  where 5.1 would still record one. Thread environments are not
  emulated.

## Verdict

With the prelude installed, the realistic 5.1 script surface — the
removed stdlib names and function environments — behaves as on the
official runtime. The remaining risk is formatting-level drift
(`tostring` on integral floats, `%d` on floats), which surfaces as
wrong label text rather than load failures.

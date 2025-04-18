"""This code is slightly modified from https://til.simonwillison.net/webassembly/python-in-a-wasm-sandbox

(c) 2025 Donovan Preston

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


from wasmtime import Config, Engine, Linker, Module, Store, WasiConfig

import os
import sys
import tempfile


WASM_PATH = "var/python-3.12.0.wasm"


if not os.path.exists(WASM_PATH):
    print("Please download https://github.com/vmware-labs/webassembly-language-runtimes/releases/download/python%2F3.12.0%2B20231211-040d5a6/python-3.12.0.wasm into sandbox/var")
    sys.exit(1)


class Result(object):
    def __init__(self, result, mem_size, data_len, consumed):
        self.result = result
        self.mem_size = mem_size
        self.data_len = data_len
        self.consumed = consumed

    def __str__(self):
        return f"""\
result:

{self.result}

mem size pages of 64kb: {self.mem_size}
data length: {self.data_len}
fuel consumed: {self.consumed}
"""


def run_python_code(code, fuel=400_000_000):
    engine_cfg = Config()
    engine_cfg.consume_fuel = True
    engine_cfg.cache = True

    linker = Linker(Engine(engine_cfg))
    linker.define_wasi()

    python_module = Module.from_file(linker.engine, WASM_PATH)

    config = WasiConfig()

    config.argv = ("python", "-c", code)
    config.preopen_dir(".", "/")

    with tempfile.TemporaryDirectory() as chroot:
        out_log = os.path.join(chroot, "out.log")
        err_log = os.path.join(chroot, "err.log")
        config.stdout_file = out_log
        config.stderr_file = err_log

        store = Store(linker.engine)

        # Limits how many instructions can be executed:
        store.set_fuel(fuel)
        store.set_wasi(config)
        instance = linker.instantiate(store, python_module)

        # _start is the default wasi main function
        start = instance.exports(store)["_start"]

        mem = instance.exports(store)["memory"]

        try:
            start(store)
        except Exception as e:
            print(e)
            raise

        with open(out_log) as f:
            result = f.read()

        return Result(
            result, mem.size(store), mem.data_len(store), store.get_fuel()
        )


if __name__ == "__main__":
    for code in (
        "print('hello world')",
        "for i in range(10000): print('hello world')",
        "print('hello world')",
        "for i in range(100000): print('hello world')",
        "import sqlite3; print(sqlite3.connect(':memory:').execute('select sqlite_version()').fetchone()[0])"
    ):
        try:
            print(code)
            print("====")
            print(run_python_code(code))
        except Exception as e:
            print(e)


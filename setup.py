from setuptools import setup
from setuptools import Extension
from Cython.Build import cythonize
import sys

# 你的模块名是 ip_core，源文件是 ip_core.py
# 注意：Cython 编译 .py 文件时，通常需要把 .py 改名为 .pyx，
# 或者在 setup.py 里显式指定 .py 作为源。这里用 .pyx 更规范。
extensions = [
    Extension(
        name="ip_core",
        sources=["ip_core.pyx"],   # 见下方说明
    )
]

setup(
    name="ip_core",
    ext_modules=cythonize(
        extensions,
        compiler_directives={
            "language_level": "3",   # 你的代码是 Python 3
        },
    ),
    zip_safe=False,
)

"""Build the PyQt6 client as a CPython extension.
Usage:
    python -m pip install cython setuptools
    python setup.py build_ext --inplace
"""
from setuptools import Extension, setup
from Cython.Build import cythonize

extensions = cythonize(
    [Extension("client", ["client.py"])],
    compiler_directives={
        "language_level": 3,
        "embedsignature": True,
    },
    annotate=False,
)
setup(
    name="p2pchat-client",
    version="1.1",
    description="P2PChat v1.1 PyQt6 client extension",
    ext_modules=extensions,
    zip_safe=False,
)

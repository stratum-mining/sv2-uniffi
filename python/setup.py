#!/usr/bin/env python3

from setuptools import setup, find_packages

# Read the README if it exists
LONG_DESCRIPTION = """# sv2python
Python bindings for [Stratum V2 Reference Implementation](https://github.com/stratum-mining/stratum).
"""

setup(
    name="sv2python",
    version="0.1.0",
    description="Python bindings for Stratum v2 Reference Implementation",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    py_modules=["sv2"],
    package_data={
        "": ["*.dylib", "*.so", "*.dll"],
    },
    include_package_data=True,
    zip_safe=False,
    python_requires=">=3.7",
    install_requires=[
        "base58",
    ],
    author="The Stratum V2 Developers <stratumv2@gmail.com>",
    url="https://github.com/stratum-mining/sv2-uniffi",
    license="MIT or Apache 2.0",
)
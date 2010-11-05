#!/usr/bin/env python2.5
from distutils.core import setup, Extension

ROOT_DIR = "../"

setup(name = "msg_stub", version = "1.0", ext_modules = [Extension(name="msg_stub", sources=["msg_stub.c"])])

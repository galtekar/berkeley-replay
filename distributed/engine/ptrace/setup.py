#!/usr/bin/env python2.5
from distutils.core import setup, Extension

ROOT_DIR = "../.."

setup(name = "ptrace", version = "1.0", ext_modules = [Extension(name="ptrace", sources=["main.c"])])

#!/usr/bin/env python3
"""Reproduce owner/backend incompatibility on disposable TPM; NOT enrollment acceptance."""
from admin_credential_integration import main

if __name__ == '__main__':
    main(enrollment=True)

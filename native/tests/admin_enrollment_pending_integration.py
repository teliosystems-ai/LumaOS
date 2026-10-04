#!/usr/bin/env python3
"""Committed, vacant and mismatched pending enrollment on fresh disposable TPMs."""
from admin_credential_integration import main

if __name__ == '__main__':
    for mode in ('committed', 'vacant', 'wrong-head', 'lost-before-rename', 'lost-after-rename'):
        main(enrollment='pending-' + mode)

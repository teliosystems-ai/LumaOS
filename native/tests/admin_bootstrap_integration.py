#!/usr/bin/env python3
"""Product bootstrap receipt on an enrolled disposable TPM; fixture identity only."""
from admin_credential_integration import main

if __name__ == '__main__':
    main(enrollment='bootstrap')

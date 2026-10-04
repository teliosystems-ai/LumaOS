#!/usr/bin/env python3
"""Real PAM and kernel peers composed with the disposable TPM catalog backend.

No installed service, confinement enforcement or physical qualification claim.
"""
from admin_credential_integration import main


if __name__ == '__main__':
    main(enrollment='service-pam')

#!/usr/bin/env python3
"""Output the EICAR test file to stdout for use in demos.

Usage::

    python3 contrib/create-eicar.py > /tmp/eicar.com
    python3 contrib/create-eicar.py > /home/kaykoe/.local/share/antyswirus-demo/eicar.com
"""

import sys

sys.stdout.buffer.write(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

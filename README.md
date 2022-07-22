# robot-detect

Proof of concept attack and detection for ROBOT (Return Of
Bleichenbacher's Oracle Threat).

More Info:
* https://robotattack.org/

Dependencies
============

This script needs Python 3, the gmpy2 and the cryptography library.

Install with pip
================

To install with the needed dependencies run:

    pip install robot-detect
    
## Debian
    sudo apt install python3-pip python3-gmpy2
    pip3 install robot-detect
    
Manpage
=======
    usage: robot-detect [-h] [-r RAW | -m MESSAGE] [-a] [-p int] [-t TIMEOUT] [-q]
                        [--gcm | --cbc] [--csv]
                        host [s0] [limit]
                          
    Bleichenbacher attack
      
    positional arguments:
      host                  Target host
      s0                    Start for s0 value (default 1)
      limit                 Start for limit value (default -1)
      
    optional arguments:
      -h, --help            show this help message and exit
      -r RAW, --raw RAW     Message to sign or decrypt (raw hex bytes)
      -m MESSAGE, --message MESSAGE
                            Message to sign (text)
      -a, --attack          Try to attack if vulnerable
      -p int, --port int    TCP port
      -t TIMEOUT, --timeout TIMEOUT
                            Timeout
      -q, --quiet           Quiet
      --gcm                 Use only GCM/AES256.
      --cbc                 Use only CBC/AES128.
      --csv                 Output CSV format

Usage
=====
    robot-detect 172.16.217.201 -a

License
=======

This work is licensed as CC0 (public domain).

Authors
=======

The attack proof of concept code was provided by Tibor Jager.

The detection was written by the ROBOT team:

Hanno Böck, Juraj Somorovsky, Craig Young

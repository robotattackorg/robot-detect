# robot-detect

Tool to detect the ROBOT attack (Return of Bleichenbacher's Oracle Threat).

More Info:
* https://robotattack.org/

Dependencies
============

This script needs Python 3, the gmpy2 and the cryptography library.

Install with pip
================

To install with the needed dependencies run:

`pip install robot-detect`

To install with setup.py:
==================
`python setup.py install`

To run from a Python module:
===========================

1. Install with pip or setup.py
2. Run the script like

```python
import shlex
from robot_detect import main as robot_main
results = robot_main(shlex.split("<host_name> -p <port>"))
```

`results` will be a string of what would have been printed if the server is vulnerable.

License
=======

This work is licensed as CC0 (public domain).

Authors
=======

Hanno Böck, Juraj Somorovsky, Craig Young

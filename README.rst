==========
LAMPalyzer
==========

Simple script to spot macroscopic problems on a **LAMP** server.
This is a **readonly** procedure, it doesn't do any modification on machine.
Tries to depend only on basic linux tools and be POSIX compliant to maximize portability.

Remote execution 
================
If you have to check many machines you can avoid to downlad this script on them and execute it from your working PC:: 

    ssh root@target 'sh' < lampalyzer.sh

Or if you have to use root::

    ssh root@target 'echo "rootpass" | sudo -Sv && sh' < lampalyzer.sh

Unfortunately colors don't work when the script is used this way (neither with ssh -t option) :-( (Fixs are welcome!)

Contribute
==========
Pull requests that add new checks or fix issues are welcome, encouraged, and credited.

The only important thing is to follow these instructions to mantain POSIX compatibility https://wiki.ubuntu.com/DashAsBinSh

Contributors
------------
`m4oc <https://github.com/m4oc>`_ added queue check for various MTAs

Disclaimer
==========

All trademarks, copyrights and other forms of intellectual property belong to their respective owners.

The author is not affiliated with any vendor cited.

=======
bluedos
=======

--------------------------------------------------------------
Utility for testing various Dos attacks on bluetooth headsets
--------------------------------------------------------------

:Authors: - poonam shelke<s.poonam@iitg.ac.in>
          - nitish kalan<nk221212@gmail.com>
          
:Version: v1

----------------
Bluedos Testbed
----------------
Usage:
bluedos [-p protocol] [-s size] [-i iterationcount] [-a attack] [-f] <bdaddr>
-p  protocol type (l2ping || hcitool)
-i  For number of iteration attack will be on. Default : infinite
-a  Attack type : l2ping [ping , connection] || hcitool [name , info , lecc , cc , leinfo]
-f  Flood ping (delay = 0)


RESOURCES
=========

http://www.bluez.org

REPORTING BUGS
==============

npsolves@gmail.com
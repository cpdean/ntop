a tool like htop for monitoring network traffic on a host.

Try it out

```
ip a  # get the list of network interfaces (ifconfig also works)

# notes:
# - my network card is called 'wlp2s0'
# - you need sudo because you will be able to see packets belonging to other
processe on your machine
# - also i need to pop a 'which cargo' in there because my sudo profile does not
have cargo in its path

# look at packets!
sudo `which cargo` run wlp2s0

```

some day it will track:

* total bandwidth sent/recv
* per-host bandwidth sent/recv
* looking at additional data in packets
* monitoring which processes are dealing with the traffic

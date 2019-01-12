* Parse ARP packets:
    - IpNextHeaderProtocol(101)
    - IpNextHeaderProtocol(102)
    - IpNextHeaderProtocol(113)
    - IpNextHeaderProtocol(130)
    - IpNextHeaderProtocol(133)
    - IpNextHeaderProtocol(136)
    - IpNextHeaderProtocol(141)
    - IpNextHeaderProtocol(153)
    - IpNextHeaderProtocol(16)
    - IpNextHeaderProtocol(162)
    - IpNextHeaderProtocol(169)
    - IpNextHeaderProtocol(17)
    - IpNextHeaderProtocol(182)
    - IpNextHeaderProtocol(188)
    - IpNextHeaderProtocol(2)
    - IpNextHeaderProtocol(207)
    - IpNextHeaderProtocol(225)
    - IpNextHeaderProtocol(226)
    - IpNextHeaderProtocol(232)
    - IpNextHeaderProtocol(249)
    - IpNextHeaderProtocol(40)
    - IpNextHeaderProtocol(56)
    - IpNextHeaderProtocol(79)
    - IpNextHeaderProtocol(8)
    - IpNextHeaderProtocol(94)
    - IpNextHeaderProtocol(95)

* have it print more info than just source/dest
    - print out size of data
        - problem: I don't know what things mean in the different network
          layers, so here are what i interpret the layers to mean and what I
          might need to be sourcing in order to count stuff:
          ethernet packet: packet_size
          ipv4 packet: packet size, total_length
          tcp packet: packet size, 




* parse a Igmp packet (IpNextHeaderProtocol(17)
* parse a SSCOPMCE packet (IpNextHeaderProtocol(128))
    - pdf https://www.itu.int/rec/T-REC-Q.2111-199912-I
* instead of ip addr, find human readable addr
  * getaddrinfo of https://docs.rs/dns-lookup/1.0.0/dns_lookup/
    * maybe bring this in, vendor it or something
* listening to an interface provides a tx and a rx. today i'm only looking at rx
  but you should be able to look at tx at the same time!
  * this might involve more than one thread, finally!
  * this will involve some new decisions in how to display the difference
    between tx and rx channels:
    * all in one stream?
    * show both streams side-by-side?
    * figure out a way to pair tx and complimentary rx packets? (maybe just
      displaying them sorted by time is enough, or matching send/recv addr

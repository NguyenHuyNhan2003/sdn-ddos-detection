# Iperf to server using udp

# client gui UDP den h1
iperf -c 10.0.0.1 -u -b 100M -t 10 -i 1  

#server h1
iperf -s -u -i 1 -p 5001 &   
ping 10.0.0.2

# ICMP flood
# hping3 -1 -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1

# UDP flood
# hping3 -2 -V -d 120 -w 64 --rand-source --flood 10.0.0.1 

# SYN flood
# hping3 -S -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1

# TCP flood
# hping3 -A -V -d 120 -w 64 -p 80 --rand-source --flood 10.0.0.1

# Iperf to server using udp
iperf -c 10.0.0.1 -u -b 100M -t 10 -i 1
iperf -s -u -i 1 -p 5001 &
ping 10.0.0.2

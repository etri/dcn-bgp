<img src="/images/topology.GIF" width="50%" height="%40">

# /DCN/R1 Configuration  
## MW-NFD Face Creation  
nfdc face create udp4://10.0.1.2  
nfdc face create udp4://10.0.3.3  
nfdc face create udp4://10.0.5.5  
## DCN-BGP Configuration  
bgpd> enable  
bgpd# configure terminal  
bgpd(config)# router dbgp 100  
bgpd(config-router)# bgp router-name /DCN/R1  
bgpd(config-router)# neighbor /DCN/R2 remote-as 100 uri udp4://10.0.1.2:6363  
bgpd(config-router)# neighbor /DCN/R3 remote-as 100 uri udp4://10.0.3.3:6363  
bgpd(config-router)# neighbor /DCN/R5 remote-as 200 uri udp4://10.0.5.5:6363  

bgpd(config-router)# neighbor /DCN/R2 route-reflector-client  
bgpd(config-router)# neighbor /DCN/R3 route-reflector-client  
# /DCN/R2 Configuration  
## MW-NFD Face Creation  
nfdc face create udp4://10.0.1.1  
nfdc face create udp4://10.0.2.4  
2) DCN-BGP Configuration  
bgpd> enable  
bgpd# configure terminal  
bgpd(config)# router dbgp 100  
bgpd(config-router)# bgp router-name /DCN/R2  
bgpd(config-router)# neighbor /DCN/R1 remote-as 100 uri udp4://10.0.1.1:6363  
bgpd(config-router)# neighbor /DCN/R4 remote-as 300 uri udp4://10.0.2.4:6363  
bgpd# show dcn bgp  
bgpd# show dcn bgp neighbors  
bgpd# show dcn bgp summary  
# /DCN/R3 Configuration  
## MW-NFD Face Creation  
nfdc face create udp4://10.0.3.1  
nfdc face create udp4://10.0.4.4  
## DCN-BGP Configuration  
bgpd> enable  
bgpd# configure terminal  
bgpd(config)# router dbgp 100  
bgpd(config-router)# bgp router-name /DCN/R3  
bgpd(config-router)# neighbor /DCN/R1 remote-as 100 uri udp4://10.0.3.1:6363  
bgpd(config-router)# neighbor /DCN/R4 remote-as 300 uri udp4://10.0.4.4:6363  
# /DCN/R4 Configuration  
## MW-NFD Face Creation  
nfdc face create udp4://10.0.2.2  
nfdc face create udp4://10.0.4.3  
## DCN-BGP Configuration  
bgpd> enable  
bgpd# configure terminal  
bgpd(config)# router dbgp 300  
bgpd(config-router)# bgp router-name /DCN/R4  
bgpd(config-router)# neighbor /DCN/R2 remote-as 100 uri udp4://10.0.2.2:6363  
bgpd(config-router)# neighbor /DCN/R3 remote-as 100 uri udp4://10.0.4.3:6363  
bgpd(config-router)# network /youtube  
bgpd(config-router)# neighbor /DCN/R3 weight 1000  
bgpd(config-router)# neighbor /DCN/R4 weight 3000  
# /DCN/R5 Configuration  
## MW-NFD Face Creation  
nfdc face create udp4://10.0.5.1  
## DCN-BGP Configuration  
bgpd> enable  
bgpd# configure terminal  
bgpd(config)# router dbgp 200  
bgpd(config-router)# bgp router-name /DCN/R5  
bgpd(config-router)# neighbor /DCN/R1 remote-as 100 uri udp4://10.0.5.1:6363  
bgpd(config-router)# network /netflix  

import netaddr

def get_ips_from_subnet(subnet_range):
    subnet = netaddr.IPNetwork(subnet_range)
    return [str(ip) for ip in subnet]
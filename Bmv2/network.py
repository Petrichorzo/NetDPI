from p4utils.mininetlib.network_API import NetworkAPI

net = NetworkAPI()

# Network general options
net.setLogLevel('info')

# Network definition
net.addP4Switch('s1')
# net.addP4Switch('s2')
#net.setP4Source('s1','./p4src/pattern_prefilter.p4')
net.setP4Source('s1','./p4src/filter.p4')
net.setP4Source('s2','./p4src/pattern_verificaiton.p4')
net.setP4CliInput('s1', './s1-commands.txt')
net.setP4CliInput('s2', './s2-commands.txt')

net.addHost('h1')
net.addHost('h2')
net.addHost('h3')
net.addLink('s1', 'h1',delay="0ms",loss=0,bw=1)
net.addLink('s1', 's2',delay="0ms",loss=0,bw=1)
net.addLink('s1', 'h2',delay="0ms",loss=0,bw=1)
net.addLink('s2', 'h3',delay="0ms",loss=0,bw=1)

# Assignment strategy
# net.l2()

net.setIntfPort('s1', 'h1', 1)
net.setIntfPort('h1', 's1', 0)
net.setIntfPort('s1', 's2', 2)
net.setIntfPort('s2', 's1', 0)
net.setIntfPort('s1', 'h2', 3)
net.setIntfPort('h2', 's1', 0)
net.setIntfPort('s2', 'h3', 2)

net.setIntfIp('h1', 's1', '10.0.0.1/24')
net.setIntfIp('h2', 's1', '10.0.0.2/24')
net.setIntfIp('h3', 's2', '10.0.0.3/24')

net.setIntfMac('h1', 's1', '00:00:00:00:00:01')
net.setIntfMac('h2', 's1', '00:00:00:00:00:02')
net.setIntfMac('s1', 'h1', '00:00:00:00:00:05')
net.setIntfMac('s1', 'h2', '00:00:00:00:00:06')

net.setIntfMac('s2', 's1', '00:00:00:00:00:03')
net.setIntfMac('s1', 's2', '00:00:00:00:00:04')
net.setIntfMac('s2', 'h3', '00:00:00:00:00:09')
net.setIntfMac('h3', 's2', '00:00:00:00:00:10')
# Nodes general options
#net.disablePcapDumpAll()
net.enableLogAll()
net.enablePcapDumpAll()
# net.enableLogAll()
net.enableCli()
net.startNetwork()

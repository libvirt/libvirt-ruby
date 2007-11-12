require 'test/unit'

$:.unshift(File::join(File::dirname(__FILE__), "..", "lib"))
$:.unshift(File::join(File::dirname(__FILE__), "..", "ext", "libvirt"))
require 'libvirt'

class TestConnect < Test::Unit::TestCase

    TEST_CAPS = "<capabilities>\n  <host>\n    <cpu>\n      <arch>i686</arch>\n      <features>\n        <pae/>\n        <nonpae/>\n      </features>\n    </cpu>\n  </host>\n\n  <guest>\n    <os_type>linux</os_type>\n    <arch name=\"i686\">\n      <wordsize>32</wordsize>\n      <domain type=\"test\"/>\n    </arch>\n    <features>\n      <pae/>\n      <nonpae/>\n    </features>\n  </guest>\n</capabilities>\n"

    UUID = "004b96e1-2d78-c30f-5aa5-f03c87d21e69"

    NETWORK_XML = "<network>
  <name>local</name>
  <uuid>9b562b27-0969-4b39-8c96-ef7858152ccc</uuid>
  <bridge name='virbr0'/>
  <forward/>
  <ip address='172.31.122.1' netmask='255.255.255.0'>
    <dhcp>
      <range start='172.31.122.2' end='172.31.122.254'/>
    </dhcp>
  </ip>
</network>
"

    def connect_default
        c = Libvirt::open("test:///default")
        assert_not_nil(c)
        assert(! c.closed?)
        return c
    end

    def test_open
        c = connect_default
        assert_nothing_raised {
            c.close
        }
        assert(c.closed?)
        assert_nothing_raised {
            c.close
        }
        assert(c.closed?)
    end

    def test_misc
        c = connect_default
        assert_equal("Test", c.type)
        assert_equal(2, c.version)
        hostname=`hostname`.chomp
        assert_equal(hostname, c.hostname)
        assert_equal("test:///default", c.uri)
        assert_equal(32, c.maxVcpus("bogus"))
        assert_equal(TEST_CAPS, c.capabilities)
        assert_equal(1, c.numOfDomains)
        assert_equal([1], c.listDomains)
        assert_equal(0, c.numOfDefinedDomains)
        assert_equal([], c.listDefinedDomains)
        assert_equal(1, c.numOfNetworks)
        assert_equal(["default"], c.listNetworks)
        assert_equal(0, c.numOfDefinedNetworks)
        assert_equal([], c.listDefinedNetworks)

        v = Libvirt::version("Test")
        assert_equal("libvirt", v[0].type)
        assert_equal("Test", v[1].type)
    end

    def test_domain
        c = connect_default;

        dom = c.lookupDomainByID(1)
        assert_equal("test", dom.name)
        assert_equal("linux", dom.osType)
        assert_equal(UUID, dom.uuid)
        assert_equal(UUID, c.lookupDomainByUUID(UUID).uuid)
        assert_equal(UUID, c.lookupDomainByName("test").uuid)

        info = dom.info
        assert_equal(8388608, info.maxMem)
        assert_equal(2097152, info.memory)
        assert_equal(2, info.nrVirtCpu)
        assert_equal(Libvirt::Domain::RUNNING, info.state)
    end

    def test_network
        c = connect_default;

        netw = c.lookupNetworkByName("default")
        assert_equal("default", netw.name)
        assert_equal("default", netw.bridgeName)
        assert_equal(UUID, netw.uuid)
        assert_equal(UUID, c.lookupNetworkByUUID(UUID).uuid)
        assert_equal(UUID, c.lookupNetworkByName("default").uuid)
        assert_equal(false, netw.autostart)
        netw.autostart = true
        assert_equal(true, netw.autostart)
        netw.autostart = false
        assert_equal(false, netw.autostart)

        netw = c.defineNetworkXML(NETWORK_XML)
        assert_equal(NETWORK_XML, netw.xmlDesc(nil))
        assert_equal(c, netw.connection)

        assert_equal(2, c.numOfNetworks)
        assert_equal(["default", "local"], c.listNetworks)
    end
end


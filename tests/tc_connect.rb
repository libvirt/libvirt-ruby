require 'test/unit'

$:.unshift(File::join(File::dirname(__FILE__), "..", "lib"))
$:.unshift(File::join(File::dirname(__FILE__), "..", "ext", "libvirt"))
require 'libvirt'

class TestConnect < Test::Unit::TestCase

    LIBVIRT_VERSION = Libvirt::version("Xen")[0]

    TEST_CAPS_OLD = "<capabilities>\n  <host>\n    <cpu>\n      <arch>i686</arch>\n      <features>\n        <pae/>\n        <nonpae/>\n      </features>\n    </cpu>\n  </host>\n\n  <guest>\n    <os_type>linux</os_type>\n    <arch name=\"i686\">\n      <wordsize>32</wordsize>\n      <domain type=\"test\"/>\n    </arch>\n    <features>\n      <pae/>\n      <nonpae/>\n    </features>\n  </guest>\n</capabilities>\n"

    TEST_CAPS_0_40_1 = "<capabilities>\n\n  <host>\n    <cpu>\n      <arch>i686</arch>\n      <features>\n        <pae/>\n        <nonpae/>\n      </features>\n    </cpu>\n    <topology>\n      <cells num='2'>\n        <cell id='0'>\n          <cpus num='8'>\n            <cpu id='0'>\n            <cpu id='2'>\n            <cpu id='4'>\n            <cpu id='6'>\n            <cpu id='8'>\n            <cpu id='10'>\n            <cpu id='12'>\n            <cpu id='14'>\n          </cpus>\n        </cell>\n        <cell id='1'>\n          <cpus num='8'>\n            <cpu id='1'>\n            <cpu id='3'>\n            <cpu id='5'>\n            <cpu id='7'>\n            <cpu id='9'>\n            <cpu id='11'>\n            <cpu id='13'>\n            <cpu id='15'>\n          </cpus>\n        </cell>\n      </cells>\n    </topology>\n  </host>\n\n  <guest>\n    <os_type>linux</os_type>\n    <arch name='i686'>\n      <wordsize>32</wordsize>\n      <domain type='test'>\n      </domain>\n    </arch>\n    <features>\n      <pae/>\n      <nonpae/>\n    </features>\n  </guest>\n\n</capabilities>\n"

    if LIBVIRT_VERSION.major >= 0 &&
            LIBVIRT_VERSION.minor >= 4 &&
            LIBVIRT_VERSION.release >= 1
        TEST_CAPS = TEST_CAPS_0_40_1
    else
        TEST_CAPS = TEST_CAPS_OLD
    end

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

    def test_node_info
        ni = connect_default.node_get_info
        assert_equal(2, ni.nodes)
        assert_equal(16, ni.cpus)
        assert_equal(2, ni.threads)
        assert_equal(2, ni.sockets)
        assert_equal(1400, ni.mhz)
        assert_equal(2, ni.cores)
        assert_equal("i686", ni.model)
    end

    def test_misc
        c = connect_default
        assert_equal("Test", c.type)
        assert_equal(2, c.version)
        hostname=`hostname`.chomp
        assert_equal(hostname, c.hostname)
        assert_equal("test:///default", c.uri)
        assert_equal(32, c.max_vcpus("bogus"))
        assert_equal(TEST_CAPS, c.capabilities)
        assert_equal(1, c.num_of_domains)
        assert_equal([1], c.list_domains)
        assert_equal(0, c.num_of_defined_domains)
        assert_equal([], c.list_defined_domains)
        assert_equal(1, c.num_of_networks)
        assert_equal(["default"], c.list_networks)
        assert_equal(0, c.num_of_defined_networks)
        assert_equal([], c.list_defined_networks)

        v = Libvirt::version("Test")
        assert_equal("libvirt", v[0].type)
        assert_equal("Test", v[1].type)
    end

    def test_domain
        c = connect_default;

        dom = c.lookup_domain_by_id(1)
        assert_equal("test", dom.name)
        assert_equal("linux", dom.os_type)
        assert_equal(UUID, dom.uuid)
        assert_equal(UUID, c.lookup_domain_by_uuid(UUID).uuid)
        assert_equal(UUID, c.lookup_domain_by_name("test").uuid)

        info = dom.info
        assert_equal(8388608, info.max_mem)
        assert_equal(2097152, info.memory)
        assert_equal(2, info.nr_virt_cpu)
        assert_equal(Libvirt::Domain::RUNNING, info.state)

        dom.memory = info.memory/2
        dom.vcpus = 1
        info = dom.info
        assert_equal(2097152/2, info.memory)
        assert_equal(1, info.nr_virt_cpu)
    end

    def test_network
        c = connect_default;

        netw = c.lookup_network_by_name("default")
        assert_equal("default", netw.name)
        assert_equal("default", netw.bridge_name)
        assert_equal(UUID, netw.uuid)
        assert_equal(UUID, c.lookup_network_by_uuid(UUID).uuid)
        assert_equal(UUID, c.lookup_network_by_name("default").uuid)
        assert_equal(false, netw.autostart)
        netw.autostart = true
        assert_equal(true, netw.autostart)
        netw.autostart = false
        assert_equal(false, netw.autostart)

        netw = c.define_network_xml(NETWORK_XML)
        assert_equal(NETWORK_XML, netw.xml_desc(nil))
        assert_equal(c, netw.connection)

        assert_equal(2, c.num_of_networks)
        assert_equal(["default", "local"], c.list_networks)
    end
end


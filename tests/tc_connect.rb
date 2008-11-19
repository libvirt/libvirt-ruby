require 'test/unit'

$:.unshift(File::join(File::dirname(__FILE__), "..", "lib"))
$:.unshift(File::join(File::dirname(__FILE__), "..", "ext", "libvirt"))
require 'libvirt'

class TestConnect < Test::Unit::TestCase

    LIBVIRT_VERSION = Libvirt::version("Test")[0]

    TEST_CAPS_OLD = "<capabilities>\n  <host>\n    <cpu>\n      <arch>i686</arch>\n      <features>\n        <pae/>\n        <nonpae/>\n      </features>\n    </cpu>\n  </host>\n\n  <guest>\n    <os_type>linux</os_type>\n    <arch name=\"i686\">\n      <wordsize>32</wordsize>\n      <domain type=\"test\"/>\n    </arch>\n    <features>\n      <pae/>\n      <nonpae/>\n    </features>\n  </guest>\n</capabilities>\n"

    TEST_CAPS_0_40_1 = "<capabilities>\n\n  <host>\n    <cpu>\n      <arch>i686</arch>\n      <features>\n        <pae/>\n        <nonpae/>\n      </features>\n    </cpu>\n    <topology>\n      <cells num='2'>\n        <cell id='0'>\n          <cpus num='8'>\n            <cpu id='0'>\n            <cpu id='2'>\n            <cpu id='4'>\n            <cpu id='6'>\n            <cpu id='8'>\n            <cpu id='10'>\n            <cpu id='12'>\n            <cpu id='14'>\n          </cpus>\n        </cell>\n        <cell id='1'>\n          <cpus num='8'>\n            <cpu id='1'>\n            <cpu id='3'>\n            <cpu id='5'>\n            <cpu id='7'>\n            <cpu id='9'>\n            <cpu id='11'>\n            <cpu id='13'>\n            <cpu id='15'>\n          </cpus>\n        </cell>\n      </cells>\n    </topology>\n  </host>\n\n  <guest>\n    <os_type>linux</os_type>\n    <arch name='i686'>\n      <wordsize>32</wordsize>\n      <domain type='test'>\n      </domain>\n    </arch>\n    <features>\n      <pae/>\n      <nonpae/>\n    </features>\n  </guest>\n\n</capabilities>\n"

    if LIBVIRT_VERSION.major >= 0 &&
            LIBVIRT_VERSION.minor >= 4 &&
            LIBVIRT_VERSION.release >= 1
        TEST_CAPS = TEST_CAPS_0_40_1
    else
        TEST_CAPS = TEST_CAPS_OLD
    end

    UUID = "4dea22b3-1d52-d8f3-2516-782e98ab3fa0"

    NETWORK_UUID = "004b96e1-2d78-c30f-5aa5-f03c87d21e69"

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

    def test_url
        "test://" + File::join(File::expand_path(File::dirname(__FILE__)),
                               "node.xml")
    end

    def connect
        c = Libvirt::open(test_url)
        assert_not_nil(c)
        assert(! c.closed?)
        return c
    end

    def test_open
        c = connect
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
        ni = connect.node_get_info
        assert_equal(4, ni.nodes)
        assert_equal(50, ni.cpus)
        assert_equal(2, ni.threads)
        assert_equal(4, ni.sockets)
        assert_equal(6000, ni.mhz)
        assert_equal(4, ni.cores)
        assert_equal("i986", ni.model)
    end

    def test_misc
        c = connect
        assert_equal("Test", c.type)
        assert_equal(2, c.version)
        hostname=`hostname`.chomp

        assert_nothing_raised {
            c.lookup_network_by_name("default").create
        }

        assert_equal(hostname, c.hostname)
        assert_equal(test_url, c.uri)
        assert_equal(32, c.max_vcpus("bogus"))
        assert(c.capabilities.size > 0)
        assert_equal(2, c.num_of_domains)
        assert_equal([1, 2], c.list_domains.sort)
        assert_equal(0, c.num_of_defined_domains)
        assert_equal([], c.list_defined_domains)
        assert_equal(1, c.num_of_networks)
        assert_equal(["default"], c.list_networks)
        assert_equal(1, c.num_of_defined_networks)
        assert_equal(["private"], c.list_defined_networks)

        v = Libvirt::version("Test")
        assert_equal("libvirt", v[0].type)
        assert_equal("Test", v[1].type)
    end

    def test_domain
        c = connect

        dom = c.lookup_domain_by_id(1)
        assert_equal("fv0", dom.name)
        assert_equal("linux", dom.os_type)
        assert_equal(UUID, dom.uuid)
        assert_equal(UUID, c.lookup_domain_by_uuid(UUID).uuid)
        assert_equal(UUID, c.lookup_domain_by_name("fv0").uuid)

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

        # pin_vcpu is not implemented in the test driver
        # enable this once it becomes available
        # dom.pin_vcpu(0,[0])

        dom.free()
        assert_raise ArgumentError do
            dom.name
        end
    end

    def test_error
        c = connect
        raised = false
        begin
            c.lookup_domain_by_id(42)
        rescue Libvirt::RetrieveError => e
            raised = true
            assert(e.message.size > 0)
            assert_equal("virDomainLookupByID", e.libvirt_function_name)
            assert_not_nil e.libvirt_message
        end
        assert(raised)
    end

    def test_network
        c = connect

        netw = c.lookup_network_by_name("default")
        assert_equal("default", netw.name)
        assert_equal("brdefault", netw.bridge_name)
        uuid = NETWORK_UUID
        assert_equal(uuid, netw.uuid)
        assert_equal(uuid, c.lookup_network_by_uuid(uuid).uuid)
        assert_equal(uuid, c.lookup_network_by_name("default").uuid)
        assert_equal(false, netw.autostart)
        netw.autostart = true
        assert_equal(true, netw.autostart)
        netw.autostart = false
        assert_equal(false, netw.autostart)

        netw = c.define_network_xml(NETWORK_XML)
        assert(netw.xml_desc.size > 0)
        assert_equal(c, netw.connection)

        netw.create
        assert_equal(1, c.num_of_networks)
        assert_equal(["local"], c.list_networks)

        netw.free
        assert_raise ArgumentError do
            netw.name
        end
    end
end

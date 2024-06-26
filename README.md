# QEMU emulation of CXL Fabric Management - what's there, what's it for, how to poke it.

**NOTE: the project is cloned from https://gitlab.com/jic23/cxl-fmapi-tests**

Given the increasing complexity of the Compute eXpress Link (CXL) emulation in QEMU and the new introduction of some Fabric Management features, it seems like a good time to write a blog to take about this stuff.

Note that we only focus on topologies where the End Points (EPs) are CXL Type 3 devices - so memory use cases. Whilst similar concepts exist for some elements of Type 1/2 devices (accelerators) they are currently simpler or mostly implementation defined.  This reflects the expectation that CXL Type 3 devices will use a 'generic' driver (based on a PCI Class code), and will be controlled with 'generic' management stacks.

### Intended Readers

* **CXL kernel driver developers** - for the Switch Mailbox CCI driver and necessary refactoring of the CXL mailbox handling)
* **QEMU developers and reviewers** - to help them understand what on earth this is all about.
* **Fabric management control software developers** - to explain what is available today.

Note that for first version of this blog at least I'll not be particularly careful about introducing every concept referred to. CXL is complex, and there are many resources on topics such as Dynamic Capacity Devices, MultiLogical Devices, CXL switch designs etc.  If there is interest I might dive deeper into these as this blog post evolves.

## What is a Fabric Manager?

In the CXL specification, Fabric Managers are a deliberately fuzzy concept. I tend to think of  them as a software entity that sits between high level datacenter / cloud orchestration systems and the low level of actual CXL hardware.  What hardware they are running on (BMC / Management Host System / Embedded in some component) is an implementation choice.  The tightest definition is on the interfaces between the Fabric Manager and the CXL components - the other side is a job for standards bodies to resolve over time (probably redfish etc).   From a QEMU based testing point of view, it is handy to do something that wouldn't typically happen in a real CXL system.  Make the Fabric Manager a software entity on the host system.  Whilst 'odd', this doesn't change any of the fundamental requirements for what needs to be done, but it does mean you can poke the system and see the results all within one emulated machine (there are proposals to support multiple interacting QEMU emulated machines...)

## What is Fabric Management in CXL

In CXL there are two fundamental types of device and system control.  In particular there are many CXL components that look much simpler to an individual CXL host (the machine making use of the memory)

* CXL host control of devices they can see (often a simplified view of a more complex device). This includes things like:
  * Identifying capabilities of the devices being provided to that host.
  * Programming of host specific aspects such as the address decoding from Host Physical Address (HPA) to Device Physical Address (DPA) in Root Bridges, Switch USPs and End Points.
  * Respond to events sent to the host as a result of Fabric Manager triggered activity.  Hotplug, Dynamic Capacity Events etc.
  * RAS handling (error reporting, some types of recovery etc)
* CXL Fabric Manager
  * Identify full capabilities of a devices - what they can provide to lots of attached hosts.
  * Control the topology - software managed hotplug of devices into different hosts / PCIe Hierarchies / MLD control.
  * Preparing a device for presentation to a host.
  * Configuring Dynamic Capacity for a given host, and triggering the host side flows to add or remove it.
  * RAS handling.

## Physical and tunneled interfaces.

In CXL there are several types of CCI (Component Control Interface), used for different purposes.

### Primary and Secondary Mailbox

**Transport:** PCI read and write to BAR memory.

**Target:** CXL Type 3 SLD (all LDs look like Single Logical Device - SLD) to the host.

Used for host control - these are fundamental part of the host interface and have been emulated for a long time.  So why mention them here?  Multi Head Devices (MHDs) were introduced in CXL r3.0 and include the option to tunnel to an LD-Pool management Logical Device (LD).  This is another type of CCI.

_Supported in QEMU but without the MHD tunneling aspect_

### Switch Mailbox CCI

**Transport:** PCI read and write to BAR memory on a PCIe function (typically additional function next to the USP)

**Target: ** CXL Switches

Some BMCs / Fabric managers are connected to CXL switches over PCIe.  This provides an inband mechanism for control of the switches.  Note that typical Switch Mailbox CCI will provide tunneling commands to send MCTP over PCIe VDM out on the downstream ports, thus acting as the starting point for fabric management of both the switch and all devices connected to a switch.  Similar, a OoB Switch CCI accessed via MCTP can provide tunneling facilities. This allows for the same model to be used if a BMC is connected to the switch via inband PCIe or via MCTP over PCIe VDM or via a MCTP over a bus such as I2C.
However, as we can see the interface presented by the Linux kernel has some differences.
  
### Out of band (OoB) CCI accessed via MCTP

**Transports:** 
* Confusingly might be carried via PCIe Vendor Defined Messages (VDM) over the PCIe link, but that is not exposed to the host via normal PCIe methods (host interfaces for this do exist, but more often this is used by a BMC piggy backing on the PCIe topology.  There are no emulate or standards defined Host MCTP over PCIe VDM interfaces - hopefully one will come along in the future - or someone will publish their datasheets.  However, this is also used for tunneling from a Switch Mailbox CCI.
* Separately buses - typically a serial bus such as I2C or I3C (also KCS, ethernet etc).  So far in QEMU we have an MCTP capable I2C controller (aspeed-i2c) which also has kernel support. That is what we are using for the CXL OoB interface emulation.

**Targets**
* Type 3 SLD
* Type3 MLD - FM owned LD
* Switch

**Used by:**
*  Fabric Manager to control the overall CXL topology 
*  BMC (or really simple FM) to access devices for management prior to host booting - things like provision of label storage area.

### LD CCI within a device accessed via tunneling.

**Transports:**  FM-API Tunnel management command used to get from an FM-Owned LD CCI to specific LD (the entity presented to the host). 

**Targets:** An individual logical devices.

Used to provision a particular LD for use by a host.  Similar usecases as for an OoB CCI on an SLD.

### Pool Management LD on a Multi Head Device

**Transports:** FM-API Tunnel management command used to get from a Primary Mailbox on one of the MHD upstream PCIe ports to the Pool Management LD.

**Targets:** This CCI provides similar resources to an FM-Owned LD on an MLD but with additional facilities to deal with the multiple upstream ports on an MHD each of which could be acting as either an SLD or an MLD

This is the big daddy of CCIs. For now we don't support a standards compliant MHD in QEMU.

# Trying it out!

Lets assume you want all the toys. Today that requires out of tree patches for kernel and qemu.

## Kernel Patches Needed

Note that COMPILE_TEST is needed to enable the ASPEED_I2C driver on x86. (thanks Adam!)

I'm testing today on v6.6-rc6 but will update these series as needed.

As the i2c controller used is aspeed-i2c and the upstream version of that only works with device tree some additional patches are needed (one of which is a horrible hack).
https://lore.kernel.org/all/20230531100600.13543-1-Jonathan.Cameron@huawei.com/ 

~~~text
Jonathan Cameron (7):
  i2c: acpi: set slave mode flag
  i2c: aspeed: Use platform_get_irq() instead of opencoding
  i2c: aspeed: Don't report error when optional dt bus-frequency not
    supplied
  i2c: aspeed: use a function pointer type def for clk_reg_val callback
  i2c: aspeed: switch to generic fw properties.
  i2c: aspeed: Set the fwnode for the adap->dev
  HACK: i2c: aspeed: Comment clock out and make reset optional
~~~

 For the CXL switch CCI support you will also need:
 https://lore.kernel.org/linux-cxl/20231016125323.18318-1-Jonathan.Cameron@huawei.com/

~~~text
Jonathan Cameron (4):
  cxl: mbox: Preparatory move of functions to core/mbox.c and cxlmbox.h
  cxl: mbox: Factor out the mbox specific data for reuse in switch cci
  PCI: Add PCI_CLASS_SERIAL_CXL_SWITCH_CCI class ID to pci_ids.h
  cxl/pci: Add support for stand alone CXL Switch mailbox CCI
 ~~~

## QEMU tree suggested

The need to use the aspeed-i2c controller and ACPI etc means a few things that are definitely not upstreamable for now even if the actual emulation of the CXL components is posted for upstream.
Longer term I have some ideas on how to solve this but for now I suggest grabbing: https://gitlab.com/jic23/qemu/-/tree/cxl-2023-10-16

That should provide you with aspeed-i2c support on bother arm-virt (plus ARM support in general) and on i386/pc for x86_64 based testing.
Note I mostly test with ARM64 so there may be gremlins on x86 that I haven't noticed yet.

# Compiling the test tool.

~~~text
gcc cxl-mctp-test.c -o cxl-mctp-test
~~~
Should work as long as you have fairly recent kernel headers installed.

# Machine configuration.

My examples are going to be ARM64 based, but it should be straight forwards to adjust them for x86.

Assuming you have a suitable kernel image, tianocore binary and root FS.

A simple test config with a CXL switch with 2 type 3 and 1 PCIe device below it.

~~~text
./qemu-system-aarch64 -M virt,gic-version=3,cxl=on -m 4g,maxmem=8G,slots=8 -cpu max -smp 4 \
 -kernel Image  -bios QEMU_EFI.fd \
 -drive if=none,file=full.qcow2,format=qcow2,id=hd \
 -device virtio-blk-pci,drive=hd \
 -nographic -no-reboot -append 'root=/dev/vda2 fsck.mode=skip' \
 -object memory-backend-file,id=cxl-mem1,mem-path=/tmp/t3_cxl1.raw,size=256M \
 -object memory-backend-file,id=cxl-lsa1,mem-path=/tmp/t3_lsa1.raw,size=1M \
 -object memory-backend-file,id=cxl-mem2,mem-path=/tmp/t3_cxl2.raw,size=16M \
 -object memory-backend-file,id=cxl-lsa2,mem-path=/tmp/t3_lsa2.raw,size=1M \
 -device pxb-cxl,bus_nr=12,bus=pcie.0,id=cxl.1,hdm_for_passthrough=true \
 -device cxl-rp,port=0,bus=cxl.1,id=cxl_rp_port0,chassis=0,slot=2 \
 -device cxl-upstream,port=2,sn=1234,bus=cxl_rp_port0,id=us0,addr=0.0,multifunction=on, \
 -device cxl-switch-mailbox-cci,bus=cxl_rp_port0,addr=0.1,target=us0 \
 -device cxl-downstream,port=0,bus=us0,id=swport0,chassis=0,slot=4 \
 -device cxl-downstream,port=1,bus=us0,id=swport1,chassis=0,slot=5 \
 -device cxl-downstream,port=3,bus=us0,id=swport2,chassis=0,slot=6 \
 -device cxl-type3,bus=swport0,memdev=cxl-mem1,id=cxl-pmem1,lsa=cxl-lsa1,sn=3 \
 -device cxl-type3,bus=swport2,memdev=cxl-mem2,id=cxl-pmem2,lsa=cxl-lsa2,sn=4 \
 -machine cxl-fmw.0.targets.0=cxl.1,cxl-fmw.0.size=4G,cxl-fmw.0.interleave-granularity=1k \
 -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=4,target=us0 \
 -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=5,target=cxl-pmem1 \
 -device i2c_mctp_cxl,bus=aspeed.i2c.bus.0,address=6,target=cxl-pmem2 \
 -device virtio-rng-pci,bus=swport1
~~~

## Configure the MCTP over I2C network and poke the CXL devices.

Before we can talk to the devices via MCTP over I2C we need to configure it.

* Address 8 - The Switch
* Address 9 - One of the type 3 devices (FM Owned LD)
* Address 10 - The other type 3 device (FM Owned LD)

~~~text
# Bring up the link
mctp link set mctpi2c0 up
# Assign an address to the aspeed-i2c controller
mctp addr add 50 dev mctpi2c0
# Assign a neetwork ID to the link (11)
mctp link set mctpi2c0 net 11
# Start the daemon that uses dbus for configuration.
systemctl start mctpd.service
# Assign an EID to the EP (hard coded I2C address is 0x4d)
busctl call xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp au.com.CodeConstruct.MCTP AssignEndpoint say mctpi2c0 1 0x4
busctl call xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp au.com.CodeConstruct.MCTP AssignEndpoint say mctpi2c0 1 0x5
busctl call xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp au.com.CodeConstruct.MCTP AssignEndpoint say mctpi2c0 1 0x6
# Check it worked by dumping some state.
busctl introspect xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp/11/8 xyz.openbmc_project.MCTP.Endpoint
busctl introspect xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp/11/9 xyz.openbmc_project.MCTP.Endpoint
busctl introspect xyz.openbmc_project.MCTP /xyz/openbmc_project/mctp/11/10 xyz.openbmc_project.MCTP.Endpoint
~~~

Poke the devices via the various CXL FM-API (and type 3 device bindings) over MCTP over I2C. Note this makes use of tunnelling to access the various entities below each connection point of the MCTP/I2C interfaces.

Exactly what gets printed will change as this tool and the emulation develop further.
~~~test
# ./cxl-fmapi-test 8
Information and Status: Identify Request...
Infostat Identify Response:
        Type: Switch
        VID:19e5 DID:a128
        Serial number: 0x4d2
Supported Logs: Get Request...
Get Supported Logs Response 1
        Command Effects Log available
Command Effects Log Requested
Command Effects Log
        [0001]
        [0400]
        [0401]
        [5100]
        [5101]
        [5300]
NB: Next query is expected to fail due to wrong MCTP message type
Physical Switch: Identify Switch Device Request...
Error code in response 3
trans fun failed
Physical Switch: Identify Switch Device Request...
Physical Switch Identify Switch Device Response:
        Num tot vppb 4, Num Bound vPPB 4, Num HDM dec per USP 4
        Ports 4
        ActivePortMask 0f0000000000000000000000000000000000000000000000000000000
0000000
Physical Switch Port State Requested
Physical Switch Port State Response - num ports 4:
Port00:
        Port state: DSP
        Connected Device CXL Version: CXL 2.0
        Connected Device Type: CXL type 3 pooled device
        Supported CXL Modes: 2.0
        Maximum Link Width: 1 Negotiated Width 1
        Supported Speeds:
        LTSSM: L2
Port01:
        Port state: DSP
        Connected Device CXL Version: CXL 2.0
        Connected Device Type: PCIe device
        Supported CXL Modes: 2.0
        Maximum Link Width: 1 Negotiated Width 1
        Supported Speeds:
        LTSSM: L2
Port02:
        Port state: USP
        Supported CXL Modes: 2.0
        Maximum Link Width: 1 Negotiated Width 1
        Supported Speeds:
        LTSSM: L2
Port03:
        Port state: DSP
        Connected Device CXL Version: CXL 2.0
        Connected Device Type: CXL type 3 pooled device
        Supported CXL Modes: 2.0
        Maximum Link Width: 1 Negotiated Width 1
        Supported Speeds:
        LTSSM: L2
Query the FM-Owned LD.....
Information and Status: Identify Request...
Infostat Identify Response:
        Type: Type3
        VID:8086 DID:0d93 SubsysVID:1af4 SubsysID:1100
        Serial number: 0x3
Supported Logs: Get Request...
Get Supported Logs Response 1
        Command Effects Log available
Command Effects Log Requested
Command Effects Log
        [0001]
        [0300]
        [0400]
        [0401]
        [5300]
Query LD0.......
Information and Status: Identify Request...
2 Level tunnel of opcode 0001
Infostat Identify Response:
        Type: Type3
        VID:8086 DID:0d93 SubsysVID:1af4 SubsysID:1100
        Serial number: 0x3
Supported Logs: Get Request...
2 Level tunnel of opcode 0400
Get Supported Logs Response 1
        Command Effects Log available
Command Effects Log Requested
2 Level tunnel of opcode 0401
Command Effects Log
        [0001]
        [0400]
        [0401]
Query the FM-Owned LD.....
Information and Status: Identify Request...
Infostat Identify Response:
        Type: Type3
        VID:8086 DID:0d93 SubsysVID:1af4 SubsysID:1100
        Serial number: 0x4
Supported Logs: Get Request...
Get Supported Logs Response 1
        Command Effects Log available
Command Effects Log Requested
Command Effects Log
        [0001]
        [0300]
        [0400]
        [0401]
        [5300]
Query LD0.......
Information and Status: Identify Request...
2 Level tunnel of opcode 0001
Infostat Identify Response:
        Type: Type3
        VID:8086 DID:0d93 SubsysVID:1af4 SubsysID:1100
        Serial number: 0x4
Supported Logs: Get Request...
2 Level tunnel of opcode 0400
Get Supported Logs Response 1
        Command Effects Log available
Command Effects Log Requested
2 Level tunnel of opcode 0401
Command Effects Log
        [0001]
        [0400]
        [0401]
~~~

Similarly can poke the direct connections to the type 3 devices with 

~~~text
# ./cxl-fmapi-test 9
...
# ./cxl-fmapi-test 10
...
~~~

## Find the CXL Switch Mailbox CCI

Look in /sys/bus/cxl/devices/ for switchX. Whilst it is typically switch0, occasionally it ends up as switch1 because of shared IDs with other CXL components.

~~~text
 # ./cxl-fmapi-test 0 0
~~~

Result not repeated because it looks much like the case above.

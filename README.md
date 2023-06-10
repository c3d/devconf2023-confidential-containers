# Confidential Containers

This repository contains various steps that will be presented during the
DevConf.cz 2023 [_Confidential Computing, from host to workload_][sched]
session.

[sched]: https://devconfcz2023.sched.com/event/1MYgS/confidential-computing-from-host-to-workload

## System pre-requisites

The demonstration is made on an AMD SEV-SNP capable system, running Fedora 38 with kernel 6.2.14.

``` shell
# cat /etc/os-release
NAME="Fedora Linux"
VERSION="38 (Thirty Eight)"
ID=fedora
VERSION_ID=38
VERSION_CODENAME=""
PLATFORM_ID="platform:f38"
PRETTY_NAME="Fedora Linux 38 (Thirty Eight)"
ANSI_COLOR="0;38;2;60;110;180"
LOGO=fedora-logo-icon
CPE_NAME="cpe:/o:fedoraproject:fedora:38"
DEFAULT_HOSTNAME="fedora"
HOME_URL="https://fedoraproject.org/"
DOCUMENTATION_URL="https://docs.fedoraproject.org/en-US/fedora/f38/system-administrators-guide/"
SUPPORT_URL="https://ask.fedoraproject.org/"
BUG_REPORT_URL="https://bugzilla.redhat.com/"
REDHAT_BUGZILLA_PRODUCT="Fedora"
REDHAT_BUGZILLA_PRODUCT_VERSION=38
REDHAT_SUPPORT_PRODUCT="Fedora"
REDHAT_SUPPORT_PRODUCT_VERSION=38
SUPPORT_END=2024-05-14


# cat /proc/cmdline
BOOT_IMAGE=(hd0,gpt2)/vmlinuz-6.2.14-300.fc38.x86_64 root=UUID=3cc75089-14bf-4ff5-a05f-c71c9082b6b3 ro rootflags=subvol=root rhgb quiet


# cat /proc/cpuinfo
## Only relevant part of the output
vendor_id       : AuthenticAMD
model name      : AMD EPYC 7313 16-Core Processor
flags           : sev sev_es


# dmesg | grep -i sev
[    2.313184] ccp 0000:22:00.1: sev enabled
[    2.406858] ccp 0000:22:00.1: SEV API:1.52 build:4
[    5.268688] SEV supported: 502 ASIDs
[    5.268689] SEV-ES supported: 7 ASIDs
```

## Install required software

We will need the following sofware to perform our testing

1. `kcli`, a tool to quickly create and setup virtual machines and clusters
2. `libvirt`, `libvirt-client` and `libvirt-client-qemu` for tools like `virsh`
   (also used by `kcli` as a back-end).
3. `qemu-kvm` for virtualization
4. `sevctl` to control the SEV specific aspects of the machine

```shell
# dnf copr enable karmab/kcli
# dnf install kcli libvirt libvirt-client libvirt-client-qemu qemu-kvm sevctl
# systemctl enable --now libvirtd

```

## Checking that SEV is working

We can check that SEV is available and working, and also that libvirt is aware
of SEV and SEV-capable.

```shell
# sevctl ok
[ PASS ] - AMD CPU
[ PASS ]   - Microcode support
[ PASS ]   - Secure Memory Encryption (SME)
[ PASS ]   - Secure Encrypted Virtualization (SEV)
[ PASS ]     - Encrypted State (SEV-ES)
[ PASS ]     - Secure Nested Paging (SEV-SNP)
[ PASS ]       - VM Permission Levels
[ PASS ]         - Number of VMPLs: 4
[ PASS ]     - Physical address bit reduction: 5
[ PASS ]     - C-bit location: 51
[ PASS ]     - Number of encrypted guests supported simultaneously: 509
[ PASS ]     - Minimum ASID value for SEV-enabled, SEV-ES disabled guest: 8
[ PASS ]     - SEV enabled in KVM: enabled
[ PASS ]     - Reading /dev/sev: /dev/sev readable
[ PASS ]     - Writing /dev/sev: /dev/sev writable
[ PASS ]   - Page flush MSR: ENABLED
[ PASS ] - KVM supported: API version: 12
[ PASS ] - Memlock resource limit: Soft: 8388608 | Hard: 8388608


# lsmod | grep kvm_amd
kvm_amd               204800  0
kvm                  1318912  1 kvm_amd
ccp                   147456  1 kvm_amd


# virsh domcapabilities | sed '/<sev/,/<\/sev/!d'
    <sev supported='yes'>
      <cbitpos>51</cbitpos>
      <reducedPhysBits>1</reducedPhysBits>
      <maxGuests>502</maxGuests>
      <maxESGuests>7</maxESGuests>
      <cpu0Id>0LvkNfSo7nyy9XmUeHWatFWqk7uC0GA5Y48H7UfwVRu/Ekin9Dzqg1olDTGOFK/8hZFRkN9D0/9geQ1PrrvMvQ==</cpu0Id>
    </sev>
```

## Setup kcli

There are few steps to run the first time you want to use `kcli`, notably
setting up a pool for VM images, as well as a default network (you can easily
manage multiple networks).

```shell
# kcli create pool -p /var/lib/libvirt/images default
Creating pool default...
# kcli create network -c 192.168.12.0/24 default
# kcli list network
+---------+--------+-----------------+------+---------+------+
| Network |  Type  |       Cidr      | Dhcp |  Domain | Mode |
+---------+--------+-----------------+------+---------+------+
| default | routed | 192.168.12.0/24 | True | default | nat  |
+---------+--------+-----------------+------+---------+------+
# kcli list vm
+------+--------+----+--------+------+---------+
| Name | Status | Ip | Source | Plan | Profile |
+------+--------+----+--------+------+---------+
+------+--------+----+--------+------+---------+
# kcli list available-images
+-----------------+
| Images          |
+-----------------+
| almalinux9      |
| arch            |
| centos7         |
| centos8stream   |
| centos9stream   |
| cirros          |
...
| ubuntu2210      |
| ubuntu2304      |
| rockylinux8     |
| rockylinux9     |
+-----------------+
```

## Create a non-confidential VM

We can now create a non-confidential VM and check that it's secrets are not
necessarily very well protected from a malicious administrator on the host.

First create the VM:
```shell
# kcli create vm testvm -i fedora38 -P numcpus=4 -P memory=8G -P rootpassword=schtroumpf
```

Then we can connect to a console to the VM and check that we can login with that
password:

```shell
# virsh console testvm
(Login with root/schtroumpf)
```

We can then leave a process running in the console with another secret:

```shell
testvm# cat .ssh/authorized_keys
(Checking that the host public key is there)
testvm# export MYSECRET=toto-titi-tata
testvm# while true; do echo $MYSECRET; sleep 1; done
(Disconnect with Control-])
```

We can also connect without password with `kcli ssh` (this is really the
recommended way):

```testvm
# kcli ssh testvm
testvm # (Perform some operations in the guest)
```

Let's now dump the memory of the VM on the host, and see what we get:

```shell
# virsh qemu-monitor-command testvm '{"execute":"dump-guest-memory","arguments":{"paging":false,"protocol":"file:/tmp/testvm_memory"}}'
# emacs /tmp/testvm_memory
```

We can then search for in-memory secrets in the guest, and we see
plenty. Notably, it is possible to:

* Find the root password
* Find the secrets stored in memory by a C program.


## Make the virtual machine confidential-compatible

We will edit the `testvm` according to instructions in the
[libvirt documentation][libvirt].

[libvirt]: https://libvirt.org/kbase/launch_security_sev.html#id12

```shell
virsh edit testvm
```

Before we can try to make the virtual machine confidential, we first need to
adjust it so that it is compatible with SEV, as follows:

* Replace the machine type with `pc-q35-3.0`
* Replace the PCI root with PCIe
* Remove all the PCI addresses and let `libvirt` reassign them
* Replace SATA with SCSI, use `virtio-scsi`
* Add an OVMF binary in the `os` section:
  ```xml
  <os>
    <type arch='x86_64' machine='pc-q35-3.0'>hvm</type>
    <loader readonly='yes' type='pflash'>/usr/share/edk2/ovmf/OVMF_CODE.fd</loader>
    [...]
  </os>
  ```
* Add a `<memoryBacking>` element:
  ```
  <memoryBacking>
    <locked/>
  </memoryBacking>
  ```
* Change devices to `virtio` with IOMMU enabled (skiping `rng`, not defined for
  us)
  ```
  <domain>
    ...
    <controller type='virtio-serial' index='0'>
      <driver iommu='on'/>
    </controller>
    <controller type='scsi' index='0' model='virtio-scsi'>
      <driver iommu='on'/>
    </controller>
    ...
    <memballoon model='virtio'>
      <driver iommu='on'/>
    </memballoon>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
      <driver iommu='on'/>
    </rng>
    ...
  <domain>
  ```
* Adjust the `virtio-net` interface:
  ```
  domain>
    ...
    <interface type='network'>
       ...
      <model type='virtio'/>
      <driver iommu='on'/>
      <rom enabled='no'/>
    </interface>
    ...
  <domain>
  ```

## Prepare the host for SEV

We need to prepare the host to run SEV.

First, reset the SEV certificates on the system, and generate a new set:
```shell
# sevctl reset
# sevctl verify
PDH EP384 D256 c34923e63d6182c42a91bb2c10ad3350ac47f1638af737145ae438209bccea81
 ⬑ PEK EP384 E256 0cf9b8a7246687f66ac08f16117201d37b3071c7abe4df9d2caa8bf059d9f85a
   •⬑ OCA EP384 E256 3088bfa7393172a7ce744efa3dae7a69a4f09723e3eb813d8c5f2c11411877d5
    ⬑ CEK EP384 E256 6897f0ec8a195c12bc42a73887baa614a5053a498006381084e4fec271662f4a
       ⬑ ASK R4096 R384 95cba79ba3c77daea79f741bade8156a50b1c59f6d6fda104d16dd264729f5ee8989522f3711fc7c84719921ceb31bc0
         •⬑ ARK R4096 R384 569da618dfe64015c343db6d975e77b72fdeacd16edd02d9d09b889b8f0f1d91ffa5dfbd86f7ac574a1a7883b7a1e737

 • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs
```

The acronyms used above can be found in the [confidential containers acronyms catalog][acronyms]

* PDH: Platform Diffie-Helman Key
* PEK: Platform Endorsement Key
* OCA: Owner's Cerificate Authority
* CEK: Chip Endorsement Key
* ASK: AMD SEV Key
* ARK: AMD Root Key

[acronyms]: https://github.com/confidential-containers/documentation/wiki/Acronyms#pek

If we `sevctl verify` again, we get the same results above for everything that
belongs to the owner (OCA, PEK and PDH):

```shell
# sevctl verify
PDH EP384 D256 c34923e63d6182c42a91bb2c10ad3350ac47f1638af737145ae438209bccea81
 ⬑ PEK EP384 E256 0cf9b8a7246687f66ac08f16117201d37b3071c7abe4df9d2caa8bf059d9f85a
   •⬑ OCA EP384 E256 3088bfa7393172a7ce744efa3dae7a69a4f09723e3eb813d8c5f2c11411877d5
    ⬑ CEK EP384 E256 6897f0ec8a195c12bc42a73887baa614a5053a498006381084e4fec271662f4a
       ⬑ ASK R4096 R384 95cba79ba3c77daea79f741bade8156a50b1c59f6d6fda104d16dd264729f5ee8989522f3711fc7c84719921ceb31bc0
         •⬑ ARK R4096 R384 569da618dfe64015c343db6d975e77b72fdeacd16edd02d9d09b889b8f0f1d91ffa5dfbd86f7ac574a1a7883b7a1e737

 • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs
```

However, if `sevctl reset` is run again, then the owner's data will change:

```shell
# sevctl reset
# sevctl verify
PDH EP384 D256 e0d29866ec1e8641e083884417070826b5585cbfcddb5d63fbb6a5ddbcc4f5f1
 ⬑ PEK EP384 E256 19bf54c57b1968c7656730d8408abcfca02c70b45eff1b5f1a16257863074fe1
   •⬑ OCA EP384 E256 6222a4c2a455107afb263ecf390ff8ec267710da7e1eaf5bc055d82606f16a77
    ⬑ CEK EP384 E256 6897f0ec8a195c12bc42a73887baa614a5053a498006381084e4fec271662f4a
       ⬑ ASK R4096 R384 95cba79ba3c77daea79f741bade8156a50b1c59f6d6fda104d16dd264729f5ee8989522f3711fc7c84719921ceb31bc0
         •⬑ ARK R4096 R384 569da618dfe64015c343db6d975e77b72fdeacd16edd02d9d09b889b8f0f1d91ffa5dfbd86f7ac574a1a7883b7a1e737

 • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs
```

## Create a session to start the virtual machine

We now create a session for the VM:

```shell
# sevctl session --name testvm host.pdh 3
```

The value 3 is a _policy_, which is defined in the [documentation for the
`<launchSecurity>` element][lv-policy], and is originally documented in [chapter
3 of AMD's SEV KM API specification][amd-policy]. The value 3 we passed here
indicates we don't want to debug and share keys.

[lv-policy]: https://libvirt.org/formatdomain.html#launch-security
[amd-policy]: https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf

The `sevctl session` command creates four files that we will need for the VM
veritifcation:

```shell
# ls testvm*
testvm_godh.b64  testvm_session.b64  testvm_tek.bin  testvm_tik.bin
```

Here, two new acronyms:

* TIK: Transport Integrity Key
* TEK: Transport Encryption Key

We can now edit the virtual machine to add a `<launchSecurity>` element:

```xml
<domain>
  ...
  <launchSecurity type='sev' kernelHashes='yes'>
    <policy>0x0003</policy>
    <cbitpos>51</cbitpos>
    <reducedPhysBits>1</reducedPhysBits>
    <dhCert>[... insert godh file here ...</dhCert>
    <session>[... insert session file here ...]</session>
  </launchSecurity>
  ...
</domain>
```

The value for `<policy>` element should match what you passed to
`sevctl session` command.

We can now launch the VM in paused mode:

```shell
# virsh start testvm --paused
```

We will now get the security info for the domain:

```shell
# virsh domlaunchsecinfo testvm
```

The validation of the measurement can be done with the `virt-qemu-sec-validate`
command:

```shell
# virt-qemu-sev-validate \
  --measurement pMFvEgG869KQBqSXDppu8B9iVWjiL1rSElnfwnaBebsGnZAoUbRehC7Pj0uuF3Ra \
  --api-major 1 \
  --api-minor 52 \
  --build-id 4 \
  --policy 3 \
  --firmware /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --tik testvm_tik.bin \
  --tek testvm_tek.bin
```

This should show a message indicating that everything is OK. If so, you can
resume the VM and use it as usual.

```shell
# virsh resume testvm
```


## Checking that the guest memory is not visible to the host

With AMD encryption in place, we can dump the memory using the same procedure as
previously, and search for the secrets.

The good news is that if you run the same C program as before from an `ssh`
session. then you will not see the in-memory secrets.

The bad news is that:

* If you run the same program from the guest console, then whatever is printed
  in the console can be found in the memory dump. This is because the virtual
  console is not encrypted.

* If you look for the root password following the same procedure we just
  did, then _you will find it_. This is because we never encrypted the root disk
  (it's actually difficult to do when using `kcli`), and some key shell scripts
  used during the setup of the VM will leave behind very explicit information
  in clear:

  ```
  #cloud-config
  final_message: kcli boot finished, up $UPTIME seconds
  hostname: testvm
  ssh_pwauth: True
  disable_root: false
  ssh_authorized_keys:
  - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC1O0rX+zJ+jD784igsKe8RdB1tT/c6l+S/JBhB3RzhJQGKMKmkK/fHmFD+W7M+cX68o/Lyd/kAVOZZ859nrfzVN
  yeXt6OZVoGnK8NPEmrMRFMpPh6p5A0QS0B4+amS2kk5Kxrv6hXM94oEqxbJmJZjCFH0KLlm3qm0fIGBv8vjEfnbcYbRBzayWkHWxRG13DQyCjzNbvl2ycBwkDhrxeL8\
  5d/0Og9gRkT88cGxhdK80NhHCwy4oL/nfOGyA5ugCxkuHC3gfPr4iezI2ote+LGeG7D58Ams4cz8YKKse0PoH6E3X3cK+hglNzm87ZxddeLVHoCOYez5dQ9FAjYdQUZ\
  7w6RK8jReWHHAsizoTspJ37HFEcCSOfa+GLIsTPiQWnFSQStEY307qNRghPLg8JtzUqkLD+OX96sLpcXmYYxlS40/rcTTDtUviJvXaTCWAACZRvSfj6kXGnlVstlvhw
  xxYWtXWNgIubadAk13B9xcZKEQGBLu3k/eNuqyZ78EKPc= root@virtlab1021.lab.eng.rdu2.redhat.com
  runcmd:
  - echo root:schtroumpf | chpasswd
  ssh_pwauth: True
  ```

So we definitely want to have confidential virtual machines _use full disk
ecnryption_, otherwise the protection you get is nonexistent. Which is easier
said than done with a few common tools used to deploy VMs.


## Various errors you can get

If you do not adjust the `memoryBacking` section, you will get a message like:

```
sev_ram_block_added: failed to register region (0x7fd96e6bb000+0x20000) error 'Cannot allocate memory'
[2257701.103251] SEV: 131072 locked pages exceed the lock limit of 16384.
```

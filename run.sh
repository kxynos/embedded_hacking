#!/bin/bash
echo " - QEMU virtual enviroment - "
echo " - Emulating MIPS - "

# 1 for internet to be enabled
INTERNET=1

TAPDEV_0=tap1_0
HOSTNETDEV_0=${TAPDEV_0}
ADDRESS=192.168.5
ETH_DEV=eth0

echo "Creating TAP device ${TAPDEV_0}..."
sudo tunctl -t ${TAPDEV_0} -u ${USER}

echo "Bringing up TAP device..."
sudo ip link set ${HOSTNETDEV_0} up
sudo ip addr add ${ADDRESS}.2/24 dev ${HOSTNETDEV_0}

echo "Adding route to ${ADDRESS}.1..."
sudo ip route add ${ADDRESS}.1 via ${ADDRESS}.1 dev ${HOSTNETDEV_0}

if [ "${INTERNET}" = "1" ]
then
echo "Updating iptables with NAT (internet)..."
sudo iptables -t nat -A POSTROUTING -o ${ETH_DEV} -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i ${TAPDEV_0} -o ${ETH_DEV} -j ACCEPT
fi

function cleanup {
    pkill -P $$
    
echo "Deleting route..."
sudo ip route flush dev ${HOSTNETDEV_0}

echo "Bringing down TAP device..."
sudo ip link set ${TAPDEV_0} down

echo "Deleting TAP device ${TAPDEV_0}..."
sudo tunctl -d ${TAPDEV_0}

if [ "${INTERNET}" = "1" ]
then
echo "Deleting iptables..."
sudo iptables -t nat -D POSTROUTING -o ${ETH_DEV} -j MASQUERADE
sudo iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -D FORWARD -i ${TAPDEV_0} -o ${ETH_DEV} -j ACCEPT
fi

}

trap cleanup EXIT

echo "Starting firmware emulation... use Ctrl-a + x to exit"
sleep 1s

sudo qemu-system-mips -M malta -kernel vmlinux-3.2.0-4-4kc-malta -hda debian_wheezy_mips_standard.qcow2 -append "root=/dev/sda1 console=ttyS0" -nographic  -netdev tap,id=net0,ifname=${TAPDEV_0},script=no -device e1000,netdev=net0 -netdev socket,id=net1,listen=:2222 -device e1000,netdev=net1 

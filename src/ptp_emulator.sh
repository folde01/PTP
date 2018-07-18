#!/usr/bin/env

# Starts Android Studio AVD emulator using QEMU and tap interface.
# prereqs: create Nexus_5_API_24 in AVD Manager; tap interface (see ptp_networking.sh)
# credit to https://www.cypherpunk.at/2017/08/monitoring-android-emulator-network-traffic/

# TODO: why doesn't this work except when started manually from command line?

export LD_LIBRARY_PATH=$ANDROID_HOME/emulator/lib64:$ANDROID_HOME/emulator/lib64/qt/lib

$ANDROID_HOME/emulator/qemu/linux-x86_64/qemu-system-i386 -avd Nexus_5_API_24 -qemu -net nic,model=virtio -net tap,ifname=tap0,script=no,downscript=no

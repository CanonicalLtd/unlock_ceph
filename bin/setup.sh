#!/bin/bash

mkdir -p /tmp/unlock_ceph_dev/source
mkdir -p /tmp/unlock_ceph_dev/dest

echo test1 > /tmp/unlock_ceph_dev/source/test1
echo test2 > /tmp/unlock_ceph_dev/source/test2
echo test3 > /tmp/unlock_ceph_dev/dest/test3

ln -s /tmp/unlock_ceph_dev/dest/test3 /tmp/unlock_ceph_dev/source/test3

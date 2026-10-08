package tun

import (
	"encoding/binary"
	"os"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	androidSocketStorageMapPath   = "/sys/fs/bpf/netd_shared/map_netd_sk_storage"
	androidLoopbackChecksMapPath  = "/sys/fs/bpf/netd_shared/map_netd_loopback_checks_enabled_map"
	androidSocketStorageKeyLength = 4
)

func (r *autoRedirect) allowAndroidLoopbackAccess(fd int) error {
	_, err := os.Stat(androidLoopbackChecksMapPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "stat loopback checks map")
	}
	err = unix.Fchown(fd, 0, -1)
	if err != nil {
		return E.Cause(err, "change redirect listener owner")
	}
	mapDescriptor, info, err := bpfObjectGet(androidSocketStorageMapPath)
	if err != nil {
		return E.Cause(err, "open socket storage map")
	}
	defer unix.Close(mapDescriptor)
	if info.mapType != unix.BPF_MAP_TYPE_SK_STORAGE || info.keySize != androidSocketStorageKeyLength {
		return E.New("unexpected socket storage map layout: type ", info.mapType, ", key ", info.keySize)
	}
	var key [androidSocketStorageKeyLength]byte
	binary.NativeEndian.PutUint32(key[:], uint32(fd))
	err = bpfMapCall(unix.BPF_MAP_DELETE_ELEM, mapDescriptor, key[:], nil, 0)
	if err != nil && err != unix.ENOENT {
		return E.Cause(err, "remove redirect listener socket storage")
	}
	r.logger.Debug("allowed cross-user loopback access to the redirect listener")
	return nil
}

//go:build linux && !android

package tun

func (r *autoRedirect) allowAndroidLoopbackAccess(fd int) error {
	return nil
}

//go:build !windows

package windows

// FileSHA256 is unavailable off Windows.
func FileSHA256(path string) (string, error) { return "", nil }

// IsElevated is unavailable off Windows.
func IsElevated(pid uint32) (bool, error) { return false, nil }

// UserName is unavailable off Windows.
func UserName(pid uint32) (string, error) { return "", nil }

// Cwd is unavailable off Windows.
func Cwd(pid uint32) (string, error) { return "", nil }

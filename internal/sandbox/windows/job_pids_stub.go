//go:build !windows

package windows

// ListPIDs is unavailable outside Windows.
func (s *Sandbox) ListPIDs() ([]uint32, error) {
	return nil, nil
}

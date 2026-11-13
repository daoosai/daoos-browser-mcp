abi <abi/5.0>,
# Dedicated to the DAOOS Browser container. No existing host profile is changed.
# File visibility is reduced per session by bubblewrap; Docker drops ALL host
# capabilities. Namespace capabilities are needed for Chromium's native sandbox.
profile daoos-browser flags=(attach_disconnected,mediate_deleted) {
  file,
  network,
  capability,
  mount,
  umount,
  pivot_root,
  userns,
  signal,
  ptrace,
  /{,**} ix,
}

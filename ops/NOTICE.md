# Third-party policy source

`seccomp-chromium.json` starts from the official Playwright Docker policy:
https://github.com/microsoft/playwright/blob/main/utils/docker/seccomp_profile.json

DAOOS additions permit bubblewrap's namespace-local mount operations, modern
openat2/faccessat2/fchmodat2/mount_setattr calls, and make clone3 return ENOSYS so
libc uses the allowed clone fallback. Container host capabilities remain dropped.
The custom AppArmor profile is loaded only for the dedicated Browser container.

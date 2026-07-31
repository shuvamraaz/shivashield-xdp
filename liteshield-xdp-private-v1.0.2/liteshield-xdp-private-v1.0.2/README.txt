LiteShield XDP — Private Release v1.0.2

REQUIREMENTS
  - Linux kernel 5.15+ with BTF
  - x86_64 architecture
  - Valid LiteShield license key

INSTALL
  sudo ./install.sh

The installer will ask for your license key (PL-XXXX-XXXX-XXXX-XXXX).

FILES
  liteshield          — firewall binary (obfuscated)
  liteshield.bpf.o    — compiled XDP program
  install.sh          — installer
  uninstall.sh        — removal script
  configs/            — example configuration
  systemd/            — service unit
  assets/             — images
  LICENSE             — license text

COMMANDS
  liteshield load              — attach firewall (requires license)
  liteshield unload            — detach firewall
  liteshield status            — show status
  liteshield license activate  — activate license key
  liteshield license status    — show license info
  liteshield whitelist add     — whitelist IP
  liteshield blacklist add     — blacklist IP
  liteshield blackhole         — blackhole mode

# Verification

## 1.4.1

Automated checks cover TCP reassembly, binary payload preservation, multiple connections, CRC/event validation, cancellation, pause/resume timeline at original and double speed, no reconnect on pause, stop while paused, update version comparison, download progress, fallback, cancellation and SHA-256 failure.

GitHub Actions runs Go tests and vet on Windows, builds the native desktop application and verifies that its main window opens. Release builds include the pinned Wireshark and etl2pcapng components.

Actual hardware traffic, long captures, system capture drivers, administrator elevation, visual layout and a real in-place update should also be accepted on the target Windows machine using WINDOWS-VALIDATION.md. Successful cross-compilation is not proof of field capture behavior. No field captures are included in this repository or release.

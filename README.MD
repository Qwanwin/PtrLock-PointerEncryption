# PtrLock – Pointer Encryption & Validation

**Author:** [@Qwanwin](https://github.com/Qwanwin)  
**License:** MIT  
**Language:** C++11+  
**Supported OS:** Linux, Android, Windows, macOS, BSD  

---

## 📖 Overview

`PtrLock` adalah implementasi **pointer encryption** dengan dukungan validasi runtime, rekeying dinamis, dan whitelist memory range.  
Tujuannya adalah untuk **mengamankan pointer** agar tidak bisa dengan mudah dibaca atau dimodifikasi oleh attacker (misalnya melalui memory dump atau hooking).  

Fitur ini bisa digunakan di:
- Proteksi function pointer.
- Anti-hook / anti-tamper.
- Mengamankan alamat data sensitive di memory.
- Obfuscasi alamat pointer untuk reverse engineering.

---

## ✨ Features

- **Feistel 64-bit Cipher** untuk mengenkripsi alamat pointer.
- **Runtime key rotation** dengan epoch tracking.
- **Tagging & integrity check** untuk mendeteksi pointer tampering.
- **Per-pointer tweak** (random salt) agar ciphertext unik.
- **Whitelist memory ranges** untuk validasi eksekusi atau data.
- **Cross-platform random source** (`getrandom`, `/dev/urandom`, `BCryptGenRandom`, `arc4random_buf`).
- **Automatic key refresh** saat rotasi kunci.
- **Exec/Data section validation** via `/proc/self/maps` (Linux) atau `VirtualQuery` (Windows).

---

## 🛠 Build & Usage

### Linux / Android (NDK)
```bash
g++ -std=c++11 -O2 -Wall -c ptrlock.h

# PtrLock – Pointer Encryption

**Author:** [@Qwanwin](https://github.com/Qwanwin)  
**License:** MIT  
**Language:** C++11+  
**Supported OS:** Linux, Android, Windows, macOS, BSD  



## 📖 Overview

**PtrLock** is a **secure pointer encryption** implementation with runtime validation, dynamic key rotation, and optional memory range whitelisting.  
It is designed to **protect sensitive pointers** from being easily read, modified, or hijacked by attackers (e.g., through memory dumping or function hooking).  

Common use cases:
- **Protecting function pointers** from redirection/hooking.
- **Anti-tampering** for sensitive memory addresses.
- Securing **data pointers** in memory.
- **Obfuscating pointer values** against reverse engineering.



## ✨ Features

- **Feistel 64-bit cipher** for encrypting pointer values.
- **Per-pointer random tweak** (salt) for unique ciphertext.
- **Tagging & integrity check** to detect tampering.
- **Runtime key rotation** with epoch tracking.
- **Automatic re-keying** when the global key changes.
- **Whitelist memory ranges** for allowed execution or data access.
- **Cross-platform random source**:
  - Linux/Android: `getrandom()`, `/dev/urandom`
  - Windows: `BCryptGenRandom`
  - macOS/BSD: `arc4random_buf`
- **Memory permission validation**:
  - Linux: `/proc/self/maps`
  - Windows: `VirtualQuery`



## 🛠 Build Instructions

### Linux / Android (NDK)
```bash
g++ -std=c++11 -O2 -Wall -c ptrlock.h

Windows (MSVC)

cl /std:c++17 /O2 ptrlock.h bcrypt.lib

macOS / BSD

clang++ -std=c++11 -O2 ptrlock.h



📦 Usage Examples

1. Securing a Function Pointer

#include "ptrlock.h"
#include <iostream>

void secret_function() {
    std::cout << "Secret function executed!\n";
}

int main() {
    using namespace codex;

    // Encrypt a function pointer
    auto handle = CODEX_ENC_ABS(&secret_function);

    // Call the encrypted function
    CODEX_ABS_CALL(handle, void)();

    // Rotate encryption keys
    CODEX_REKEY(handle, 0);

    // Call again after rekeying
    CODEX_ABS_CALL(handle, void)();

    return 0;
}




2. Data Pointer

#include "ptrlock.h"
#include <iostream>

int main() {
    using namespace codex;

    int my_value = 42;

    // Encrypt the data pointer
    EncPtr<int> secure_ptr(&my_value);

    // Read the decrypted value
    std::cout << "Value: " << *secure_ptr.get() << "\n";

    // Rotate keys (will update the encrypted pointer)
    secure_ptr.rekey();

    std::cout << "Value after rekey: " << *secure_ptr.get() << "\n";

    return 0;
}




3. Using Whitelist Validation

#include "ptrlock.h"
#include <iostream>

void safe_function() {
    std::cout << "Safe function executed!\n";
}

int main() {
    using namespace codex;

    auto handle = CODEX_ENC_ABS(&safe_function);

    // Define allowed execution ranges
    ModuleRange ranges[] = {
        codex::make_exec_range((uintptr_t)&safe_function, 0x1000)
    };

    handle->set_whitelist(ranges, 1);

    // This will pass whitelist check
    CODEX_ABS_CALL(handle, void)();

    return 0;
}




⚙ API & Macros

Macro / Function	Description

CODEX_ENC_ABS(ptr)	Create encrypted handle from an absolute pointer.
CODEX_ABS_CALL(handle, Ret, ...)	Call an encrypted function pointer.
CODEX_ABS_PTR(handle, Type)	Get a decrypted data pointer.
CODEX_REKEY(handle, new_key)	Rotate encryption key for a specific handle.
EncPtr<T>	Type-safe encrypted pointer wrapper.





🔄 Key Rotation Flow

1. Initial key is generated when the library is first used.


2. Each pointer is encrypted with:

Global key

Random tweak

Epoch number



3. When rotate_keys() is called:

previous_key ← current_key

current_key ← new random value

Epoch number increments



4. On decryption, if the tag doesn’t match the current key,
the system will attempt decryption using the previous key.



⚠ Notes

Null pointers are stored unencrypted.

If EncPtrError::InvalidTag occurs → pointer may have been tampered with.

Execution/data validation depends on OS-level APIs (/proc/self/maps, VirtualQuery).





📜 License

MIT License – free to use, modify, and integrate into your projects.

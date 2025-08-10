#pragma once
// Author: @Qwanwin
// License: MIT
// C++11+, Linux/Android/Windows/macOS/BSD

#include <cstdint>
#include <cstddef>
#include <atomic>
#include <random>
#include <array>
#include <vector>
#include <tuple>
#include <cstdio>
#include <cstring>

#if defined(__linux__)
  #include <sys/random.h>
  #include <sys/auxv.h>
  #include <unistd.h>
  #include <fcntl.h>
#endif

#if defined(_WIN32)
  #define NOMINMAX
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
  #include <stdlib.h> 
  #include <unistd.h>
  #include <fcntl.h>
#endif

#if defined(__clang__) || defined(__GNUC__)
  #define CODEX_NOINLINE __attribute__((noinline))
  #define CODEX_HIDDEN   __attribute__((visibility("hidden")))
#else
  #define CODEX_NOINLINE
  #define CODEX_HIDDEN
#endif

#ifndef CODEX_VALIDATE_EXEC
  #define CODEX_VALIDATE_EXEC 1
#endif
#ifndef CODEX_VALIDATE_DATA
  #define CODEX_VALIDATE_DATA 1
#endif

namespace codex {


static_assert(sizeof(uint64_t)==8, "uint64_t must be 64-bit");
static_assert(sizeof(void*)==4 || sizeof(void*)==8, "Unsupported pointer size");


enum class EncPtrError { None, NullCiphertext, InvalidTag, InvalidRange, Misaligned };

static inline uint32_t rotl32(uint32_t x, unsigned r){ r&=31u; return (x<<r)|(x>>((32u-r)&31u)); }
static inline uint64_t rotl64(uint64_t x, unsigned r){ r&=63u; return (x<<r)|(x>>((64u-r)&63u)); }
static inline void barrier(const void* p){
#if defined(__clang__) || defined(__GNUC__)
  asm volatile("" : : "r"(p) : "memory");
#else
  std::atomic_signal_fence(std::memory_order_seq_cst);
#endif
  (void)p;
}


static inline uint64_t rng64(){
  static std::atomic<bool> init{false};
  static std::array<uint64_t,32> cache{};
  static std::atomic<size_t> idx{0};
  if(!init.load(std::memory_order_acquire)){
    bool ok=false;
#if defined(_WIN32)
    ok = (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(cache.data()),
                          cache.size()*sizeof(uint64_t), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0);
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(cache.data(), cache.size()*sizeof(uint64_t));
    ok = true;
#elif defined(__linux__)
    ssize_t n = getrandom(cache.data(), cache.size()*sizeof(uint64_t), 0);
    ok = (n == (ssize_t)(cache.size()*sizeof(uint64_t)));
    if(!ok){
      int fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
      if(fd>=0){ ok = (read(fd, cache.data(), cache.size()*sizeof(uint64_t)) ==
                       (ssize_t)(cache.size()*sizeof(uint64_t))); close(fd); }
    }
#else
    int fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
    if(fd>=0){ ok = (read(fd, cache.data(), cache.size()*sizeof(uint64_t)) ==
                     (ssize_t)(cache.size()*sizeof(uint64_t))); close(fd); }
#endif
    if(!ok){
      std::random_device rd;
      for(size_t i=0;i<cache.size();++i) cache[i] = (uint64_t(rd())<<32) ^ rd();
    }
    init.store(true, std::memory_order_release);
  }
  return cache[idx.fetch_add(1, std::memory_order_relaxed) & (cache.size()-1)];
}


struct KeyEpoch {
  std::atomic<uint64_t> current_key{0};
  std::atomic<uint64_t> previous_key{0};
  std::atomic<uint32_t> epoch{0};        
};
static inline KeyEpoch& key_store(){ static KeyEpoch ks; return ks; }

static inline uint64_t _ensure_key(std::atomic<uint64_t>& slot){
  uint64_t k = slot.load(std::memory_order_acquire);
  if(!k){
    uint64_t mix = rng64();
#if defined(__linux__)
    void* p = (void*)getauxval(AT_RANDOM);
    if(p) mix ^= *(uint64_t*)p;
#endif
    if(!mix) mix = 0xD00D'CAFE'1234'5678ULL;
    slot.compare_exchange_strong(k, mix, std::memory_order_release);
    if(!k) k = mix;
  }
  return k;
}
static inline uint64_t current_key(){ return _ensure_key(key_store().current_key); }
static inline uint64_t previous_key(){ return key_store().previous_key.load(std::memory_order_acquire); }
static inline uint32_t current_epoch(){ return key_store().epoch.load(std::memory_order_acquire); }


static inline void rotate_keys(uint64_t new_key=0){
  if(!new_key) new_key = rng64();
  KeyEpoch& ks = key_store();
  uint64_t cur = current_key();
  ks.previous_key.store(cur, std::memory_order_release);
  ks.current_key.store(new_key, std::memory_order_release);
  ks.epoch.fetch_add(1, std::memory_order_acq_rel);
  barrier(&ks);
}


struct feistel64 {
  static inline uint32_t F(uint32_t x, uint64_t k, unsigned round){
    uint32_t t = x ^ (uint32_t)k ^ (uint32_t)(k>>32);
    t = rotl32(t ^ (uint32_t)round, (7 + (k & 15)));
    t *= 0x9E3779B1u; t ^= (t>>16);
    return t;
  }
  static inline void make_subkeys(uint64_t k, uint64_t tweak, uint64_t sk[8]){
    uint64_t c = (k ^ tweak);
    sk[0]=rotl64(c ^ 0xA5A5F00DFACEB00CULL,17);
    sk[1]=rotl64(c ^ 0xC3C3DEADBEEF1337ULL,29);
    sk[2]=rotl64(c ^ 0xF00DBA5EBA5EBA5EULL,11);
    sk[3]=rotl64(c ^ 0xDEADBEEFDEADBEEFULL,23);
    sk[4]=rotl64(c ^ 0xCAFEBABEDECAF111ULL,31);
    sk[5]=rotl64(c ^ 0xBADDCAFE12345678ULL,37);
    sk[6]=rotl64(c ^ 0xFEEDFACE87654321ULL,41);
    sk[7]=rotl64(c ^ 0xC0DEC0DEC0DEC0DEULL,47);
  }
  static inline uint64_t enc(uint64_t v, uint64_t k, uint64_t tweak){
    uint64_t sk[8]; make_subkeys(k,tweak,sk);
    uint32_t L=(uint32_t)v, R=(uint32_t)(v>>32);
    for(unsigned r=0;r<8;++r){ uint32_t nL=R; uint32_t nR=L ^ F(R, sk[r], r+1); L=nL; R=nR; }
    return (uint64_t(R)<<32)|L;
  }
  static inline uint64_t dec(uint64_t v, uint64_t k, uint64_t tweak){
    uint64_t sk[8]; make_subkeys(k,tweak,sk);
    uint32_t L=(uint32_t)v, R=(uint32_t)(v>>32);
    for(unsigned r=8;r-- > 0;){ uint32_t pR=L; uint32_t pL=R ^ F(L, sk[r], r+1); R=pL; L=pR; }
    return (uint64_t(R)<<32)|L;
  }
};


static inline uint64_t tag64(uint64_t ciph, uint64_t tweak, uint64_t k, uint32_t epoch){
  uint64_t x = ciph ^ k ^ tweak ^ 0x6C8E9CF570932BD7ULL ^ (uint64_t(epoch) << 32);
  x ^= rotl64(x,13); x *= 0x9E3779B185EBCA87ULL;
  x ^= rotl64(x,17); x *= 0xC2B2AE3D27D4EB4FULL;
  x ^= rotl64(x,29);
  return x;
}


struct ModuleRange { uintptr_t base=0, end=0; bool exec=true, data=true; };

struct ValidatePolicy {
  bool   require_exec=false;
  bool   require_data=false;
  size_t alignment=1;
  const ModuleRange* whitelist=nullptr;
  size_t whitelist_count=0;
};


struct CODEX_HIDDEN EncPtrHandle {
  uint64_t ciphertext=0;
  uint64_t tweak=0;
  uint64_t tag=0;
  uint32_t ver=1;
  uint32_t enc_epoch=0;          
  ValidatePolicy policy{};

  EncPtrHandle() = default;
  explicit EncPtrHandle(uintptr_t p){ set(p); }

  void set(uintptr_t p){
    if(!p){ ciphertext=0; tweak=0; tag=0; ver=1; enc_epoch=current_epoch(); return; }
    tweak = rng64();
    uint64_t v=(uint64_t)p;
    v ^= rotl64(v,23) ^ 0x5BF0A8E3C2D1497ULL;
    uint64_t ck = current_key();
    ciphertext = feistel64::enc(v, ck, tweak);
    enc_epoch = current_epoch();
    tag = tag64(ciphertext, tweak, ck, enc_epoch);
    barrier(this);
  }

  void set_whitelist(const ModuleRange* r, size_t n){ policy.whitelist=r; policy.whitelist_count=n; }
  void clear_whitelist(){ policy.whitelist=nullptr; policy.whitelist_count=0; }

  bool _whitelist_ok(uintptr_t p, bool want_exec, bool want_data) const {
    if(!policy.whitelist || policy.whitelist_count==0) return true;
    for(size_t i=0;i<policy.whitelist_count;++i){
      const auto& r = policy.whitelist[i];
      if(p>=r.base && p<r.end){
        if(want_exec && !r.exec) continue;
        if(want_data && !r.data) continue;
        return true;
      }
    }
    return false;
  }

#if defined(__linux__)
  static std::vector<std::tuple<uintptr_t,uintptr_t,bool/*exec*/,bool/*write*/>>& _ranges(){
    static std::vector<std::tuple<uintptr_t,uintptr_t,bool,bool>> v; return v;
  }
  static void _refresh_maps_once(){
    static std::atomic<bool> done{false};
    if(done.load(std::memory_order_acquire)) return;
    FILE* f=fopen("/proc/self/maps","r");
    if(f){
      char line[512];
      while(fgets(line,sizeof(line),f)){
        uintptr_t s=0,e=0; char perms[5]={0};
        if(sscanf(line,"%lx-%lx %4s",&s,&e,perms)==3){
          bool r=(perms[0]=='r'), w=(perms[1]=='w'), x=(perms[2]=='x');
          if(r) _ranges().emplace_back(s,e,x,w);
        }
      }
      fclose(f);
    }
    done.store(true,std::memory_order_release);
  }
  static bool _in_exec(uintptr_t p){
    _refresh_maps_once();
    for(auto& t:_ranges()){ auto s=std::get<0>(t), e=std::get<1>(t); if(p>=s && p<e) return std::get<2>(t); }
    return false;
  }
  static bool _in_data(uintptr_t p){
    _refresh_maps_once();
    for(auto& t:_ranges()){
      auto s=std::get<0>(t), e=std::get<1>(t);
      if(p>=s && p<e){ bool x=std::get<2>(t), w=std::get<3>(t); return w || !x; }
    }
    return false;
  }
#endif

  
  bool _try_decode_with(uint64_t key, uint32_t epoch, uintptr_t& out_plain) const {
    if(!key) return false;
    if(tag64(ciphertext, tweak, key, epoch) != tag) return false;
    uint64_t v = feistel64::dec(ciphertext, key, tweak);
    v ^= rotl64(v,23) ^ 0x5BF0A8E3C2D1497ULL;
    out_plain = (uintptr_t)v;
    return true;
  }


  uintptr_t get_raw(bool require_exec, bool require_data, size_t align, EncPtrError* err=nullptr){
    if(ver!=1 || !ciphertext){ if(err)*err=EncPtrError::NullCiphertext; return 0; }

    uintptr_t p=0;
    uint64_t ck = current_key();
    uint32_t ce = current_epoch();
    
    if(_try_decode_with(ck, enc_epoch, p)){
     
    } else {
      
      uint64_t pk = previous_key();
      uint32_t pe = (enc_epoch ? enc_epoch-1 : enc_epoch);
      if(!_try_decode_with(pk, pe, p)){
        if(err)*err=EncPtrError::InvalidTag; return 0;
      }
     
     
      uint64_t v = (uint64_t)p;
      v ^= rotl64(v,23) ^ 0x5BF0A8E3C2D1497ULL;
      ciphertext = feistel64::enc(v, ck, tweak);
      enc_epoch  = ce;
      tag        = tag64(ciphertext, tweak, ck, enc_epoch);
      barrier(this);
    }

    
    if(align>1 && (p % align)!=0){ if(err)*err=EncPtrError::Misaligned; return 0; }

    
    if(!_whitelist_ok(p, require_exec, require_data)){ if(err)*err=EncPtrError::InvalidRange; return 0; }

    
#if defined(__linux__)
    if(require_exec && !_in_exec(p)){ if(err)*err=EncPtrError::InvalidRange; return 0; }
    if(require_data && !_in_data(p)){ if(err)*err=EncPtrError::InvalidRange; return 0; }
#elif defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi;
    if(!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))){ if(err)*err=EncPtrError::InvalidRange; return 0; }
    DWORD prot = mbi.Protect & 0xFF;
    if(require_exec){
      if(!(prot==PAGE_EXECUTE || prot==PAGE_EXECUTE_READ || prot==PAGE_EXECUTE_READWRITE || prot==PAGE_EXECUTE_WRITECOPY)){
        if(err)*err=EncPtrError::InvalidRange; return 0;
      }
    }
    if(require_data){
     
      if(prot==PAGE_EXECUTE || prot==PAGE_EXECUTE_READ || prot==PAGE_EXECUTE_READWRITE || prot==PAGE_EXECUTE_WRITECOPY){
        if(err)*err=EncPtrError::InvalidRange; return 0;
      }
      if(!(prot==PAGE_READONLY || prot==PAGE_READWRITE || prot==PAGE_WRITECOPY)){
        if(err)*err=EncPtrError::InvalidRange; return 0;
      }
    }
#else
    (void)require_exec; (void)require_data;
#endif
    if(err)*err=EncPtrError::None;
    return p;
  }

  template<class FnSig>
  FnSig to_fn(EncPtrError* err=nullptr){ 
    auto p = get_raw((CODEX_VALIDATE_EXEC!=0), false, alignof(void*), err);
    return reinterpret_cast<FnSig>(p);
  }
  template<class T>
  T* to_ptr(EncPtrError* err=nullptr){
    auto p = get_raw(false, (CODEX_VALIDATE_DATA!=0), (alignof(T)>1?alignof(T):1), err);
    return reinterpret_cast<T*>(p);
  }


  void rekey(uint64_t new_key=0){ rotate_keys(new_key); }
};


template<class T>
struct CODEX_HIDDEN EncPtr {
  EncPtrHandle h_;
  EncPtr() = default;
  explicit EncPtr(T* p){ h_.set((uintptr_t)p); }
  T* get(EncPtrError* e=nullptr){ return h_.to_ptr<T>(e); }
  void rekey(uint64_t new_key=0){ h_.rekey(new_key); }
  void set_whitelist(const ModuleRange* r, size_t n){ h_.set_whitelist(r,n); }
  void clear_whitelist(){ h_.clear_whitelist(); }
};


#define CODEX_ENC_ABS(fn_or_ptr) ([](){ \
  auto __p = (uintptr_t)(void*)(fn_or_ptr); \
  static ::codex::EncPtrHandle __h(__p); \
  return &__h; \
}())

#define CODEX_ABS_CALL(handle, RetType, ...) \
  ((handle)->to_fn<RetType(*)(__VA_ARGS__)>())

#define CODEX_ABS_PTR(handle, Type) \
  ((handle)->to_ptr<Type>())

#define CODEX_REKEY(handle, new_key) \
  ((handle)->rekey((new_key)))


static inline ModuleRange make_exec_range(uintptr_t base, uintptr_t size){ ModuleRange r; r.base=base; r.end=base+size; r.exec=true; r.data=false; return r; }
static inline ModuleRange make_data_range(uintptr_t base, uintptr_t size){ ModuleRange r; r.base=base; r.end=base+size; r.exec=false; r.data=true; return r; }

} // namespace codex

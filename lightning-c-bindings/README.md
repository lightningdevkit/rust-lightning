The wrapper crate and C/C++ Headers in this folder are auto-generated from the Rust-Lightning
source by the c-bindings-gen crate contained in the source tree and
[cbindgen](https://github.com/eqrion/cbindgen). They are intended to be used as a base for building
language-specific bindings, and are thus incredibly low-level and may be difficult to work with
directly.

In other words, if you're reading this, you're either writing bindings for a new language, or
you're in the wrong place - individual language bindings should come with their own documentation.

LDK C Bindings
==============

The C bindings available at include/lightning.h require inclusion of include/rust_types.h first.

All of the Rust-Lightning types are mapped into C equivalents which take a few forms, with the C
type getting an `LDK` prefix to their native Rust type names.

#### Structs
Structs are mapped into a simple wrapper containing a pointer to the native Rust-Lightning object
and a flag to indicate whether the object is owned or only a reference. Such mappings usually
generate a `X_free` function which must be called to release the allocated resources. Note that
calling `X_free` will do nothing if the underlying pointer is NULL or if the `is_owned` flag is not
set.

You MUST NOT create such wrapper structs manually, relying instead on constructors which have been
mapped from equivalent Rust constructors.

Note that, thanks to the is-owned flag and the pointer being NULLable, such structs effectively
represent `RustType`, `&RustType`, and `Option<RustType>`. Check the corresponding Rust
documentation for the function or struct you are using to ensure you use the correct call semantics.
The passed struct must match the call semantics or an assertion failure or NULL pointer dereference
may occur.

For example, this is the mapping of ChannelManager.
```c
typedef struct MUST_USE_STRUCT LDKChannelManager {
   /** ... */
   LDKnativeChannelManager *inner;
   bool is_owned;
} LDKChannelManager;
```

#### Traits
Traits are mapped into a concrete struct containing a void pointer (named `this_arg` and a jump
table listing the functions which the trait must implement. The void pointer may be set to any value
and is never interpreted (or dereferenced) by the bindings logic in any way. It is passed as the
first argument to all function calls in the trait. You may wish to use it as a pointer to your own
internal data structure, though it may also occasionally make sense to e.g. cast a file descriptor
into a void pointer and use it to track a socket.

This should remind you of a C++ vtable, only written out by hand and with the class only containing
a pointer, instead of the regular class data.

Each trait additionally contains `free` and `clone` function pointers, which may be NULL. The `free`
function is passed the void pointer when the object is `Drop`ed in Rust. The `clone` function is
passed the void pointer when the object is `Clone`ed in Rust, returning a new void pointer for the
new object. If the `free` pointer is NULL, you will not receive any notification when the trait
object is no longer needed. If the `clone` pointer is NULL, we assume that the trait object may be
`memcpy()`'d to create copies. Note that if you release resources with `free` without implementing
`clone`, you will likely end up with use-after-free bugs (as copies of the original this_arg value
may still exist, unbeknownst to you).

For example, `LDKSocketDescriptor` is mapped as follows:
```c
typedef struct LDKSocketDescriptor {
   void *this_arg;
   /** ... */
   uintptr_t (*send_data)(void *this_arg, LDKu8slice data, bool resume_read);
   /** ... */
   void (*disconnect_socket)(void *this_arg);
   bool (*eq)(const void *this_arg, const void *other_arg);
   uint64_t (*hash)(const void *this_arg);
   void *(*clone)(const void *this_arg);
   void (*free)(void *this_arg);
} LDKSocketDescriptor;
```

##### Rust Trait Implementations
Rust structs that implement a trait result in the generation of an `X_as_Y` function, which takes a
C struct wrapping the Rust native object and returns a generated trait object. Such generated
objects are only valid as long as the original Rust native object has not been `free`'d or moved as
a part of a Rust function call (ie continues to be owned by the C struct). For example, to use an
`LDKInMemoryChannelKeys` as a `ChannelKeys`, `InMemoryChannelKeys_as_ChannelKeys` is exposed:

```c
LDKChannelKeys InMemoryChannelKeys_as_ChannelKeys(const LDKInMemoryChannelKeys *this_arg);
```

#### Enums
Rust "unitary" enums are mapped simply as an equivalent C enum; however, some Rust enums have
variants which contain payloads. Such enums are mapped automatically by cbindgen as a tag which
indicates the type and a union which holds the relevant fields for a given tag. An `X_free` function
is provided for the enum as a whole which automatically frees the correct fields for a give tag, and
a `Sentinel` tag is provided which causes the free function to do nothing (but which must never
appear in an enum when accessed by Rust code). The `Sentinel` tag is used by the C++ wrapper classes
to allow moving the ownership of an enum while invalidating the old copy.

For example, the unitary enum `LDKChannelMonitorUpdateErr` is mapped as follows:
```c
typedef enum LDKChannelMonitorUpdateErr {
   /** .. */
   LDKChannelMonitorUpdateErr_TemporaryFailure,
   /** .. */
   LDKChannelMonitorUpdateErr_PermanentFailure,
   /** .. */
   LDKChannelMonitorUpdateErr_Sentinel,
} LDKChannelMonitorUpdateErr;
```

and the non-unitary enum LDKErrorAction is mapped as follows:
```c
typedef enum LDKErrorAction_Tag {
   /** .. */
   LDKErrorAction_DisconnectPeer,
   /** .. */
   LDKErrorAction_IgnoreError,
   /** .. */
   LDKErrorAction_SendErrorMessage,
   /** .. */
   LDKErrorAction_Sentinel,
} LDKErrorAction_Tag;

typedef struct LDKErrorAction_LDKDisconnectPeer_Body {
   LDKErrorMessage msg;
} LDKErrorAction_LDKDisconnectPeer_Body;

typedef struct LDKErrorAction_LDKSendErrorMessage_Body {
   LDKErrorMessage msg;
} LDKErrorAction_LDKSendErrorMessage_Body;

typedef struct LDKErrorAction {
   LDKErrorAction_Tag tag;
   union {
      LDKErrorAction_LDKDisconnectPeer_Body disconnect_peer;
      LDKErrorAction_LDKSendErrorMessage_Body send_error_message;
   };
} LDKErrorAction;
```

#### Functions
Struct member functions are mapped as `Struct_function_name` and take a pointer to the mapped struct
as their first argument. Free-standing functions are mapped simply as `function_name` and take the
relevant mapped type arguments.

Functions which return `&OpaqueRustType` and which return `OpaqueRustType` are both mapped to a
function returning an owned wrapper struct. The `is_owned` flag (see above) will be set to indicate
that the pointed-to Rust object is owned or only a reference. Thus, when implementing a function
which Rust will call or calling a Rust function, you should check the Rust documentation for the
function to determine whether an owned or referenced object is expected or returned.

Similarly, when a function takes an `Option<RustType>` as a parameter or a return value, the C type
is the same as if it took only `RustType`, with the `inner` field set to NULL to indicate None. For
example, `ChannelManager_create_channel` takes an `Option<LDKUserConfig>` not an `LDKUserConfig`,
but its definition is:
```c
MUST_USE_RES ... ChannelManager_create_channel(const LDKChannelManager *this_arg, ..., LDKUserConfig override_config);
```

#### Containers
Various containers (Tuples, Vecs, Results, etc) are mapped into C structs of the form
`LDKCContainerType_ContainerElementsZ`. Inner fields are often pointers, and in the case of
primitive types, these may be allocated in C using the system allocator. See [the Rust docs on your
platform's default System allocator](https://doc.rust-lang.org/std/alloc/struct.System.html) for
 which allocator you must use. Recursive containers are possible, and simply replace the
`ContainerElements` part with `InnerContainerType_InnerContainerElementsZ`, eg
`LDKCResult_C2Tuple_SignatureCVec_SignatureZZNoneZ` represents a
`Result<(Signature, Vec<Signature>), ()>`.

#### Notes
As the bindings are auto-generated, the best resource for documentation on them is the native Rust
docs available via `cargo doc` or [docs.rs/lightning](https://docs.rs/lightning).

The memory model is largely the Rust memory model and not a native C-like memory model. Thus,
function parameters are largely only ever passed by reference or by move, with pass-by-copy
semantics only applying to primitive types. However, because the underlying types are largely
pointers, the same function signature may imply two different memory ownership semantics. Thus, you
MUST read the Rust documentation while using the C bindings. For functions which take arguments
where ownership is moved to the function scope, the corresponding `X_free` function MUST NOT be
called on the object, whereas for all other objects, `X_free` MUST be used to free resources.

LDK C++ Bindings
================

The C++ bindings available at include/lightningpp.hpp require extern "C" inclusion of lightning.h
and rust_types.h first. They represent thin wrappers around the C types which provide a few
C++-isms to make memory model correctness easier to achieve. They provide:
 * automated destructors which call the relevant `X_free` C functions,
 * move constructors both from C++ classes and the original C struct, with the original object
   cleared to ensure destruction/`X_free` calls do not cause a double-free.
 * Move semantics via the () operator, returning the original C struct and clearing the C++ object.
   This allows calls such as `C_function(cpp_object)` which work as expected with move semantics.

In general, you should prefer to use the C++ bindings if possible, as they make memory leaks and
other violations somewhat easier to avoid. Note that, because the C functions are not redefined in
C++, all functions return the C type. Thus, you must bind returned values to the equivalent C++ type
(replacing `LDKX` with `LDK::X`) to ensure the destructor is properly run. A demonstration of such
usage is available at [demo.cpp](demo.cpp).

Gotchas
=======

There are a few gotchas around future changes to Rust-Lightning which the bindings may not support.
These include:
 * Any trait method which returns a reference to a struct or inner variable cannot be called in
   parallel. This is because such functions always return a local variable stored inside the trait,
   with a call through a function pointer to get the local variable set correctly. Automatically
   generated setter functions have comments describing the potential race conditions in their
   definition.

   For example, the `ChannelKeys::pubkeys() -> &ChannelPublicKeys` function is mapped as this:

   ```c
   typedef struct LDKChannelKeys {
      ...
      LDKChannelPublicKeys pubkeys;
      /** ... */
      void (*set_pubkeys)(const LDKChannelKeys*);
	  ...
   } LDKChannelKeys;
   ```
 * Private and public keys are asserted valid at the FFI boundary. Thus, before passing any
   (untrusted) private or public key material across the boundary, ensure that they represent valid
   (ie in-range) keys.
   
**It is highly recommended that you test any code which relies on the C (or C++) bindings in
valgrind, AddressSanitizer, MemorySanitizer, or other similar tools to ensure correctness.**

Process
=======

`genbindings.sh` is currently a catch-all script for bindings - it generates the latest Rust/C/C++
code for bindings from the rust-lightning source code, builds it, and then runs various test apps.

Note that after running `genbindings.sh`, if possible, the static lib in target/debug (eg
target/debug/liblightning.a) will be linked with address sanitizer. In order to build against it,
you will need to link with `clang` with `-fsanitize=address` with the same version of LLVM as
`rustc`'s LLVM. If `genbindings.sh` failed to find a matching `clang` or you are building on an
unsupported platform, a warning noting that address sanitizer is not available will be printed.

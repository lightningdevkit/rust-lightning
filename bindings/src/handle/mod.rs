use std::marker::PhantomData;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::ptr;
use std::slice;
use std::sync::Arc;

pub(crate) mod thread_bound;

use self::thread_bound::ThreadBound;

use super::is_null::IsNull;

/*
The handles here are wrappers for `&T` and an exclusive `&mut T`.

They protect from data races, but don't protect from use-after-free bugs.
The caller is expected to maintain that invariant, which in .NET can be achieved using
`SafeHandle`s.
*/

/**
 * A shared handle that can be accessed concurrently by multiple threads.
 * 
 * The interior value can be treated like `&T`.
 * 
 * Consumers must ensure a handle is not used again after it has been deallocated.
 */
#[repr(transparent)]
pub struct HandleShared<'a, T: ?Sized>(*const T, PhantomData<&'a T>);

unsafe_impl!("The handle is semantically `&T`" => impl<'a, T: ?Sized> Send for HandleShared<'a, T> where &'a T: Send {});
unsafe_impl!("The handle is semantically `&T`" => impl<'a, T: ?Sized> Sync for HandleShared<'a, T> where &'a T: Sync {});

impl<'a, T: ?Sized + RefUnwindSafe> UnwindSafe for HandleShared<'a, T> {}
impl<'a, T> HandleShared<'a, T>
where
    HandleShared<'a, T>: Send + Sync,
{
    pub(super) fn alloc(value: T) -> Self
    where
        T: 'static,
    {
        let v = Box::new(value);
        HandleShared(Box::into_raw(v), PhantomData)
    }

    pub(super) fn as_ref(&self) -> &T {
        unsafe_block!("We own, the interior value" => { &*self.0 })
    }

    pub(super) fn as_arc(&self) -> Arc<T> {
        unsafe_block!("We own, the interior value" => Arc::from_raw(self.0))
    }

    unsafe_fn!("There are no other live references and the handle won't be used again" =>
    pub(super) fn dealloc<R>(handle: Self, f: impl FnOnce(T) -> R) -> R {
        let v = Box::from_raw(handle.0 as *mut T);
        f(*v)
    }
    );
}

/**
 * A non-shared handle that cannot be accessed by multiple threads.
 * 
 * The interior value can be treated like `&mut T`.
 * 
 * The handle is bound to the thread that it was created on to ensure
 * there's no possibility for data races.
 * 
 * Note that, if this binary calls into a wrapper code (in case of C#, that is reverse PInvoke to the dll)
 * then it's possible to mutably alias the handle from the same thread if the reverse
 * call can re-enter the FFI using the same handle. This is technically undefined behavior.
 * 
 * The handle _can_ be deallocated from a different thread than the one that created it.
 * 
 * Consumers must ensure a handle is not used again after it has been deallocated.
 */
#[repr(transparent)]
pub struct HandleExclusive<'a, T: ?Sized>(*mut ThreadBound<T>, PhantomData<&'a mut T>);

unsafe_impl!("The handle is semantically `&mut T`" => impl<'a, T: ?Sized> Send for HandleExclusive<'a, T> where &'a mut ThreadBound<T>: Send {});
unsafe_impl!("The handle uses `ThreadBound` for synchronization" => impl<'a, T: ?Sized> Sync for HandleExclusive<'a, T> where &'a mut ThreadBound<T>: Sync {});
impl<'a, T: ?Sized + RefUnwindSafe> UnwindSafe for HandleExclusive<'a, T> {}
impl<'a, T> HandleExclusive<'a, T>
where
    HandleExclusive<'a, T> : Send + Sync,
{
    pub(super) fn alloc(value: T) -> Self
    where
        T: 'static
    {
        let v = Box::new(ThreadBound::new(value));
        HandleExclusive(Box::into_raw(v), PhantomData)
    }
    pub(super) fn as_mut(&mut self) -> &mut T {
        unsafe_block!("We own the interior value" => { &mut *(*self.0).get_raw() })
    }

    unsafe_fn!("There are no other live references and the handle won't be used again" => 
    pub(super) fn dealloc<R>(handle: Self, f: impl FnOnce(T) -> R) -> R
    where
        T: Send,
    {
        let v = Box::from_raw(handle.0);
        f(v.into_inner())
    }
    );
}

/**
 * An initialized parameter passed by shared reference.
 */
#[repr(transparent)]
pub struct Ref<'a, T: ?Sized>(*const T, PhantomData<&'a T>);

impl<'a, T: ?Sized + RefUnwindSafe> UnwindSafe for Ref<'a, T> {}
unsafe_impl!("The handle is semantically `&mut T`" => impl<'a, T: ?Sized> Send for Ref<'a, T> where &'a T: Send{});

unsafe_impl!("The handle uses `ThreadBound` for synchronization" => impl<'a, T: ?Sized> Sync for Ref<'a, T> where &'a T: Sync {});

impl<'a, T: ?Sized> Ref<'a, T> {
    unsafe_fn!("The pointer must be nonnull and will remain valid" =>
    pub fn as_ref(&self) -> &T {
        &*self.0
    }
    );

    unsafe_fn!("The pointer must be nonnull" => 
    pub fn as_arc(&self) -> Arc<T> {
        Arc::from_raw(self.0)
    }
    );
}

impl<'a> Ref<'a, u8> {
    unsafe_fn!("The pointer must be nonnull, the length is correct, and will remain valid" =>
    pub fn as_bytes(&self, len: usize) -> &[u8] {
        slice::from_raw_parts(self.0, len)
    }
    );
}

/**
An initialized parameter passed by exclusive reference.
*/
#[repr(transparent)]
pub struct RefMut<'a, T: ?Sized>(*mut T, PhantomData<&'a mut T>);

impl<'a, T: ?Sized + RefUnwindSafe> UnwindSafe for RefMut<'a, T> {}

unsafe_impl!("The handle is semantically `&mut T`" => impl<'a, T: ?Sized> Send for RefMut<'a, T> where &'a mut T: Send {});
unsafe_impl!("The handle uses `ThreadBound` for synchronization" => impl<'a, T: ?Sized> Sync for RefMut<'a, T> where &'a mut T: Sync {});

impl<'a, T: ?Sized> RefMut<'a, T> {
    unsafe_fn!("The pointer must be nonnull and will remain valid" => pub fn as_mut(&mut self) -> &mut T {
        &mut *self.0
    });
}

impl<'a> RefMut<'a, u8> {
    unsafe_fn!("The pointer must be nonnull, the length is correct, and will remain valid" => pub fn as_bytes_mut(&mut self, len: usize) -> &mut [u8] {
        slice::from_raw_parts_mut(self.0, len)
    });
}

/**
An uninitialized, assignable out parameter.
*/
#[repr(transparent)]
pub struct Out<'a, T: ?Sized>(*mut T, PhantomData<&'a mut T>);

impl<'a, T: ?Sized + RefUnwindSafe> UnwindSafe for Out<'a, T> {}

unsafe_impl!("The handle is semantically `&mut T`" => impl<'a, T: ?Sized> Send for Out<'a, T> where &'a mut T: Send {});
unsafe_impl!("The handle uses `ThreadBound` for synchronization" => impl<'a, T: ?Sized> Sync for Out<'a, T> where &'a mut T: Sync {});

impl<'a, T> Out<'a, T> {
    unsafe_fn!("The pointer must be nonnull and valid for writes" =>
    pub fn init(&mut self, value: T) {
        ptr::write(self.0, value);
    }
    );
}

impl<'a> Out<'a, u8> {
    unsafe_fn!("The pointer must be nonnull, not overlap the slice, must be valid for the length of the slice, and valid for writes" =>
    pub fn init_bytes(&mut self, value: &[u8]) {
        ptr::copy_nonoverlapping(value.as_ptr(), self.0, value.len());
    }
    );

    unsafe_fn!("The slice must never be read from and must be valid for the length of the slice" =>
    pub fn as_uninit_bytes_mut(&mut self, len: usize) -> &mut [u8] {
        slice::from_raw_parts_mut(self.0, len)
    }
    );
}

impl<'a, T: ?Sized> IsNull for HandleExclusive<'a, T> {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<'a, T: ?Sized + Sync> IsNull for HandleShared<'a, T> {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<'a, T: ?Sized> IsNull for Ref<'a, T> {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<'a, T: ?Sized + Sync> IsNull for RefMut<'a, T> {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}

impl<'a, T: ?Sized> IsNull for Out<'a, T> {
    fn is_null(&self) -> bool {
        self.0.is_null()
    }
}
// src/async_defer.rs
use std::future::Future;
use std::pin::Pin;

/// AsyncDefer executes an async block on drop (once).
pub struct AsyncDefer<F, Fut>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    cleanup_fn: Option<F>,
}

impl<F, Fut> AsyncDefer<F, Fut>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    pub fn new(f: F) -> Self {
        Self { cleanup_fn: Some(f) }
    }
}

impl<F, Fut> Drop for AsyncDefer<F, Fut>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn drop(&mut self) {
        if let Some(f) = self.cleanup_fn.take() {
            tokio::spawn(f());
        }
    }
}

/// AsyncDeferMut executes an async block on drop or when called manually (reusable FnMut).
pub struct AsyncDeferMut<F, Fut>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    cleanup_fn: Option<F>,
}

impl<F, Fut> AsyncDeferMut<F, Fut>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    pub fn new(f: F) -> Self {
        Self { cleanup_fn: Some(f) }
    }

    pub async fn run_now(&mut self) {
        if let Some(mut f) = self.cleanup_fn.take() {
            f().await;
        }
    }
}

impl<F, Fut> Drop for AsyncDeferMut<F, Fut>
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    fn drop(&mut self) {
        if let Some(mut f) = self.cleanup_fn.take() {
            tokio::spawn(async move {
                f().await;
            });
        }
    }
}

/// AsyncDeferStack holds a LIFO stack of async cleanup blocks (FnOnce).
pub struct AsyncDeferStack {
    stack: Vec<Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
}

impl AsyncDeferStack {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    pub fn push<F, Fut>(&mut self, f: F)
    where
        F: FnOnce() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.stack.push(Box::new(move || Box::pin(f())));
    }

    fn drain_all(mut stack: Vec<Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>) -> impl Future<Output = ()> + Send {
        async move {
            while let Some(f) = stack.pop() {
                f().await;
            }
        }
    }

    pub async fn run_all(&mut self) {
        let stack = std::mem::take(&mut self.stack);
        Self::drain_all(stack).await;
    }
}

impl Drop for AsyncDeferStack {
    fn drop(&mut self) {
        let stack = std::mem::take(&mut self.stack);
        tokio::spawn(Self::drain_all(stack));
    }
}

/// AsyncDeferStackMut holds a LIFO stack of async cleanup blocks (FnMut).
pub struct AsyncDeferStackMut {
    stack: Vec<Box<dyn FnMut() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>,
}

impl AsyncDeferStackMut {
    pub fn new() -> Self {
        Self { stack: Vec::new() }
    }

    pub fn push<F, Fut>(&mut self, mut f: F)
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        self.stack.push(Box::new(move || Box::pin(f())));
    }

    fn drain_all(mut stack: Vec<Box<dyn FnMut() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>>) -> impl Future<Output = ()> + Send {
        async move {
            while let Some(mut f) = stack.pop() {
                f().await;
            }
        }
    }

    pub async fn run_all(&mut self) {
        let stack = std::mem::take(&mut self.stack);
        Self::drain_all(stack).await;
    }
}

impl Drop for AsyncDeferStackMut {
    fn drop(&mut self) {
        let stack = std::mem::take(&mut self.stack);
        tokio::spawn(Self::drain_all(stack));
    }
}

// Macros

/// Defines an unnamed AsyncDefer (drop-only)
#[macro_export]
macro_rules! async_defer {
    ($($body:tt)*) => {
        let _guard = $crate::async_defer::AsyncDefer::new(|| async move { $($body)* });
    };
}

/// Defines a named AsyncDeferMut (can call `.run_now().await` manually)
#[macro_export]
macro_rules! async_defer_mut {
    ($name:ident, $($body:tt)*) => {
        let mut $name = $crate::async_defer::AsyncDeferMut::new(|| async move { $($body)* });
    };
}

/// Defines a named AsyncDeferStack (drop-safe LIFO cleanup stack using FnOnce)
#[macro_export]
macro_rules! async_defer_stack {
    ($name:ident) => {
        let mut $name = $crate::async_defer::AsyncDeferStack::new();
    };
}

/// Defines a named AsyncDeferStackMut (drop-safe LIFO cleanup stack using FnMut)
#[macro_export]
macro_rules! async_defer_stack_mut {
    ($name:ident) => {
        let mut $name = $crate::async_defer::AsyncDeferStackMut::new();
    };
}

/// Pushes a one-time async block onto an AsyncDeferStack
#[macro_export]
macro_rules! async_defer_push {
    ($stack:expr, $($body:tt)*) => {
        $stack.push(|| async move { $($body)* });
    };
}

/// Pushes a reusable async block onto an AsyncDeferStackMut
#[macro_export]
macro_rules! async_defer_push_mut {
    ($stack:expr, $($body:tt)*) => {
        $stack.push(|| async move { $($body)* });
    };
}
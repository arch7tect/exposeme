#[macro_export]
macro_rules! guard {
    ($($field:ident),+ => $cleanup:block) => {
        {
            $(let $field = $field.clone();)+

            let cleanup_fn = move || {
                tokio::spawn(async move {
                    if let Err(_) = tokio::time::timeout(
                        std::time::Duration::from_secs(5),
                        async move { $cleanup }
                    ).await {
                        tracing::error!("Async drop timeout for guard in {}", module_path!());
                    }
                });
            };

            struct Guard<F: FnOnce()>(Option<F>);

            impl<F: FnOnce()> Drop for Guard<F> {
                fn drop(&mut self) {
                    if let Some(f) = self.0.take() {
                        f();
                    }
                }
            }

            Guard(Some(cleanup_fn))
        }
    };
}
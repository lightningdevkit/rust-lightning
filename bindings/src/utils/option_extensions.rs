pub(crate) trait OptionMutExt<T> {
    /**
    Map and mutate an option in place.
    */
    fn map_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut T);

    /**
    Replace an option if it doesn't contain a value.
    */
    fn or_else_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce() -> Option<T>;
}

impl<T> OptionMutExt<T> for Option<T> {
    fn map_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut T),
    {
        match *self {
            Some(ref mut t) => f(t),
            None => (),
        }

        self
    }

    fn or_else_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce() -> Option<T>,
    {
        if self.is_none() {
            *self = f();
        }

        self
    }
}
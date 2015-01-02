#![macro_escape]

macro_rules! fixed_vec(
    ($t:ident, $arrt: ty, $len:expr) => (
        #[deriving(Copy)]
        pub struct $t([$arrt,..$len]);

        impl<S: ::std::hash::Writer> Hash<S> for $t {
            fn hash(&self, state: &mut S) {
                let &$t(a) = self;
                a.hash(state)
            }
        }

        impl PartialEq for $t {
            fn eq(&self, other: &$t) -> bool {
                let &$t(a) = self;
                let &$t(b) = other;
                a[].eq(b[])
            }
        }

        impl Eq for $t {}

        impl PartialOrd for $t {
            fn partial_cmp(&self, other: &$t) -> Option<Ordering> {
                let &$t(a) = self;
                let &$t(b) = other;
                a[].partial_cmp(b[])
            }
        }

        impl Clone for $t {
            fn clone(&self) -> $t {
                let mut new_vec: [$arrt, ..$len] = [0, .. $len];
                let &$t(a) = self;
                for (x,y) in new_vec.iter_mut().zip(a.iter()) {
                    *x = y.clone();
                }
                $t(new_vec)
            }
        }

    );
);

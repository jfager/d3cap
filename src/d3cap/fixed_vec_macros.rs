#![macro_escape]

macro_rules! fixed_vec(
    ($t:ident, $arrt: ty, $len:expr) => (
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
                a.as_slice().eq(&b.as_slice())
            }
        }

        impl Eq for $t {}

        impl PartialOrd for $t {
            fn lt(&self, other: &$t) -> bool {
                let &$t(a) = self;
                let &$t(b) = other;
                a.as_slice().lt(&b.as_slice())
            }
        }

        impl Clone for $t {
            fn clone(&self) -> $t {
                let mut new_vec: [$arrt, ..$len] = [0, .. $len];
                let &$t(a) = self;
                for (x,y) in new_vec.mut_iter().zip(a.iter()) {
                    *x = y.clone();
                }
                $t(new_vec)
            }
        }

    );
)

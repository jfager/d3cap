#[macro_escape];

macro_rules! fixed_vec(
    ($t:ident, $arrt: ty, $len:expr) => (

        struct $t([$arrt,..$len]);

        impl IterBytes for $t {
            fn iter_bytes(&self, lsb0: bool, f: std::to_bytes::Cb) -> bool {
                self.as_slice().iter_bytes(lsb0, f)
            }
        }

        impl Eq for $t {
            fn eq(&self, other: &$t) -> bool {
                self.as_slice().eq(&other.as_slice())
            }
        }

        impl Ord for $t {
            fn lt(&self, other: &$t) -> bool {
                self.as_slice().lt(&other.as_slice())
            }
        }

        impl Clone for $t {
            fn clone(&self) -> $t {
                let mut new_vec: [$arrt, ..$len] = [0, .. $len];
                for (x,y) in new_vec.mut_iter().zip((**self).iter()) {
                    *x = y.clone();
                }
                $t(new_vec)
            }
        }

    );
)
#[feature(macro_rules)];

#[macro_escape];

macro_rules! fixed_vec_iter_bytes(
    ($t:ty) => (
        impl IterBytes for $t {
            fn iter_bytes(&self, lsb0: bool, f: std::to_bytes::Cb) -> bool {
                self.as_slice().iter_bytes(lsb0, f)
            }
        }
    );
)

macro_rules! fixed_vec_eq(
    ($t:ty) => (
        impl Eq for $t {
            fn eq(&self, other: &$t) -> bool {
                self.as_slice().eq(&other.as_slice())
            }
        }
    );
)

macro_rules! fixed_vec_ord(
    ($t:ty) => (
        impl Ord for $t {
            fn lt(&self, other: &$t) -> bool {
                self.as_slice().lt(&other.as_slice())
            }
        }
    );
)

macro_rules! fixed_vec_clone(
    ($t:ident, $arrt: ty, $len:expr) => (
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
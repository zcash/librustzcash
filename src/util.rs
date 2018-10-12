macro_rules! impl_binops {
    ($name:ident) => {
        impl<'a, 'b> Sub<&'b $name> for &'a $name {
            type Output = $name;

            fn sub(self, other: &'b $name) -> $name {
                let mut tmp = *self;
                tmp -= other;
                tmp
            }
        }

        impl<'a, 'b> Mul<&'b $name> for &'a $name {
            type Output = $name;

            fn mul(self, other: &'b $name) -> $name {
                let mut tmp = *self;
                tmp *= other;
                tmp
            }
        }

        impl<'a, 'b> Add<&'b $name> for &'a $name {
            type Output = $name;

            fn add(self, other: &'b $name) -> $name {
                let mut tmp = *self;
                tmp += other;
                tmp
            }
        }

        impl<'b> Sub<&'b $name> for $name {
            type Output = $name;

            fn sub(self, other: &'b $name) -> $name {
                let mut tmp = self;
                tmp -= other;
                tmp
            }
        }

        impl<'b> Mul<&'b $name> for $name {
            type Output = $name;

            fn mul(self, other: &'b $name) -> $name {
                let mut tmp = self;
                tmp *= other;
                tmp
            }
        }

        impl<'b> Add<&'b $name> for $name {
            type Output = $name;

            fn add(self, other: &'b $name) -> $name {
                let mut tmp = self;
                tmp += other;
                tmp
            }
        }

        impl<'a> Sub<$name> for &'a $name {
            type Output = $name;

            fn sub(self, other: $name) -> $name {
                let mut tmp = *self;
                tmp -= &other;
                tmp
            }
        }

        impl<'a> Mul<$name> for &'a $name {
            type Output = $name;

            fn mul(self, other: $name) -> $name {
                let mut tmp = *self;
                tmp *= &other;
                tmp
            }
        }

        impl<'a> Add<$name> for &'a $name {
            type Output = $name;

            fn add(self, other: $name) -> $name {
                let mut tmp = *self;
                tmp += &other;
                tmp
            }
        }

        impl Sub<$name> for $name {
            type Output = $name;

            fn sub(self, other: $name) -> $name {
                let mut tmp = self;
                tmp -= &other;
                tmp
            }
        }

        impl Mul<$name> for $name {
            type Output = $name;

            fn mul(self, other: $name) -> $name {
                let mut tmp = self;
                tmp *= &other;
                tmp
            }
        }

        impl Add<$name> for $name {
            type Output = $name;

            fn add(self, other: $name) -> $name {
                let mut tmp = self;
                tmp += &other;
                tmp
            }
        }
    };
}

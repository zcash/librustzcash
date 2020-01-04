# 0.1.1

Added `clear_cofactor` methods to `G1Projective` and `G2Projective`. If the crate feature `endo`
is enabled the G2 cofactor clearing will use the curve endomorphism technique described by
[Budroni-Pintore](https://ia.cr/2017/419). If the crate feature `endo` is _not_ enabled then
the code will simulate the effects of the Budroni-Pintore cofactor clearing in order to keep
the API consistent. In September 2020, when patents US7110538B2 and US7995752B2 expire, the
endo feature will be made default. However, for now it must be explicitly enabled.

# 0.1.0

Initial release.

//! # Design of BLS12-381
//! ## Fixed Generators
//!
//! Although any generator produced by hashing to $\mathbb{G}_1$ or $\mathbb{G}_2$ is
//! safe to use in a cryptographic protocol, we specify some simple, fixed generators.
//!
//! In order to derive these generators, we select the lexicographically smallest
//! valid $x$-coordinate and the lexicographically smallest corresponding $y$-coordinate,
//! and then scale the resulting point by the cofactor, such that the result is not the
//! identity. This results in the following fixed generators:
//!
//! 1. $\mathbb{G}_1$
//!     * $x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507$
//!     * $y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569$
//! 2. $\mathbb{G}_2$
//!     * $x = 352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 + 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758 u$
//!     * $y = 1985150602287291935568054521177171638300868978215655730859378665066344726373823718423869104263333984641494340347905 + 927553665492332455747201965776037880757740193453592970025027978793976877002675564980949289727957565575433344219582 u$
//!
//! This can be derived using the following sage script:
//!
//! ```norun
//! param = -0xd201000000010000
//! def r(x):
//!     return (x**4) - (x**2) + 1
//! def q(x):
//!     return (((x - 1) ** 2) * ((x**4) - (x**2) + 1) // 3) + x
//! def g1_h(x):
//! 	return ((x-1)**2) // 3
//! def g2_h(x):
//!     return ((x**8) - (4 * (x**7)) + (5 * (x**6)) - (4 * (x**4)) + (6 * (x**3)) - (4 * (x**2)) - (4*x) + 13) // 9
//! q = q(param)
//! r = r(param)
//! Fq = GF(q)
//! ec = EllipticCurve(Fq, [0, 4])
//! def psqrt(v):
//! 	assert(not v.is_zero())
//! 	a = sqrt(v)
//! 	b = -a
//! 	if a < b:
//! 		return a
//! 	else:
//! 		return b
//! for x in range(0,100):
//! 	rhs = Fq(x)^3 + 4
//! 	if rhs.is_square():
//! 		y = psqrt(rhs)
//! 		p = ec(x, y) * g1_h(param)
//! 		if (not p.is_zero()) and (p * r).is_zero():
//! 			print "g1 generator: %s" % p
//! 			break
//! Fqx.<j> = PolynomialRing(Fq, 'j')
//! Fq2.<i> = GF(q^2, modulus=j^2 + 1)
//! ec2 = EllipticCurve(Fq2, [0, (4 * (1 + i))])
//! assert(ec2.order() == (r * g2_h(param)))
//! for x in range(0,100):
//! 	rhs = (Fq2(x))^3 + (4 * (1 + i))
//! 	if rhs.is_square():
//! 		y = psqrt(rhs)
//! 		p = ec2(Fq2(x), y) * g2_h(param)
//! 		if (not p.is_zero()) and (p * r).is_zero():
//! 			print "g2 generator: %s" % p
//! 			break
//! ```

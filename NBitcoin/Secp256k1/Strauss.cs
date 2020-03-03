#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	unsafe struct StraussPointState
	{
		internal Scalar na_1, na_lam;
		internal fixed int wnaf_na_1[130];
		internal fixed int wnaf_na_lam[130];
		internal int bits_na_1;
		internal int bits_na_lam;
		internal int input_pos;
	}
	unsafe struct StraussState
	{
		internal GroupElementJacobian* prej;
		internal FieldElement* zr;
		internal GroupElement* pre_a;
		internal GroupElement* pre_a_lam;
		internal StraussPointState* ps;
	}
}
#nullable restore
#endif

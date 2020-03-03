using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class SecpRecoverableECDSASignature
	{
		private readonly Scalar r;
		private readonly Scalar s;
		private readonly int recid;

		public SecpRecoverableECDSASignature(in Scalar r, in Scalar s, int recid)
		{
			this.r = r;
			this.s = s;
			this.recid = recid;
		}

		public static bool TryCreateFromCompact(ReadOnlySpan<byte> in64, int recid, out SecpRecoverableECDSASignature sig)
		{
			sig = null;
			if (SecpECDSASignature.TryCreateFromCompact(in64, out var compact) && compact is SecpECDSASignature)
			{
				sig = new SecpRecoverableECDSASignature(compact.r, compact.s, recid);
				return true;
			}
			return false;
		}

		public void Deconstruct(out Scalar r, out Scalar s, out int recid)
		{
			r = this.r;
			s = this.s;
			recid = this.recid;
		}
	}
}

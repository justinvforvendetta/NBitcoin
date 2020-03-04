#if HAS_SPAN
#nullable enable
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
		public SecpRecoverableECDSASignature(SecpECDSASignature sig, int recid)
		{
			if (sig == null)
				throw new ArgumentNullException(nameof(sig));
			this.r = sig.r;
			this.s = sig.s;
			this.recid = recid;
		}

		public static bool TryCreateFromCompact(ReadOnlySpan<byte> in64, int recid, out SecpRecoverableECDSASignature sig)
		{
			sig = null;
			if (SecpECDSASignature.TryCreateFromCompact(in64, out var compact) && compact is SecpECDSASignature)
			{
				sig = new SecpRecoverableECDSASignature(compact, recid);
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

		public void WriteToSpanCompact(Span<byte> out32, out int recid)
		{
			if (out32.Length < 64)
				throw new ArgumentException(paramName: nameof(out32), message: "out32 should be 32 bytes");
			recid = this.recid;
			r.WriteToSpan(out32);
			s.WriteToSpan(out32.Slice(32));
		}

		public SecpECDSASignature ToSignature()
		{
			return new SecpECDSASignature(r, s, false);
		}
	}
}
#nullable disable
#endif

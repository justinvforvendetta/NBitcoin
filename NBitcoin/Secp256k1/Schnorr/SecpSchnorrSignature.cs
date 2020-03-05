﻿#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class SecpSchnorrSignature
	{
		internal readonly FieldElement rx;
		internal readonly Scalar s;

		internal SecpSchnorrSignature(FieldElement rx, Scalar s)
		{
			this.rx = rx;
			this.s = s;
		}

		public static bool TryCreate(ReadOnlySpan<byte> in64, out SecpSchnorrSignature? signature)
		{
			signature = null;
			if (in64.Length < 64)
				return false;
			if (FieldElement.TryCreate(in64.Slice(0, 32), out var fe) &&
				new Scalar(in64.Slice(32, 32), out int overflow) is Scalar scalar && overflow == 0)
			{
				signature = new SecpSchnorrSignature(fe, scalar);
				return true;
			}
			return false;
		}

		public void WriteToSpan(Span<byte> out64)
		{
			if (out64.Length < 64)
				throw new ArgumentException(paramName: nameof(out64), message: "out64 should be at least 64 bytes");
			rx.WriteToSpan(out64.Slice(0, 32));
			s.WriteToSpan(out64.Slice(32, 32));
		}
	}
}
#endif

#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	partial class ECPrivKey
	{
		public bool TrySignRecoverable(ReadOnlySpan<byte> msg32, Span<byte> recoverableSignature)
		{
			return TrySignRecoverable(msg32, null, recoverableSignature);
		}
		public bool TrySignRecoverable(ReadOnlySpan<byte> msg32, INonceFunction? nonceFunction, Span<byte> recoverableSignature)
		{
			if (recoverableSignature.Length < 65)
				throw new ArgumentException(paramName: nameof(recoverableSignature), message: "recoverableSignature should be at least 65 bytes");
			if (msg32.Length != 32)
				throw new ArgumentException(paramName: nameof(msg32), message: "msg32 should be 32 bytes");
			if (this.TrySignECDSA(msg32, nonceFunction, out int recid, out SecpECDSASignature? sig) && sig is SecpECDSASignature)
			{
				sig.WriteCompactToSpan(recoverableSignature);
				recoverableSignature[64] = (byte)recid;
				return true;
			}
			return false;
		}
	}
}
#nullable disable
#endif

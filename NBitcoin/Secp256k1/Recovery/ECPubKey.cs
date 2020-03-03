#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace NBitcoin.Secp256k1
{
	partial class ECPubKey
	{
		public static bool TryRecover(Context ctx, Secp256k1.SecpRecoverableECDSASignature recoverableSig, ReadOnlySpan<byte> msg32, out ECPubKey? pubkey)
		{
			if (recoverableSig == null)
				throw new ArgumentNullException(nameof(recoverableSig));
			ctx ??= Context.Instance;
			GroupElement q;
			Scalar r, s;
			Scalar m;
			int recid;
			if (msg32.Length != 32)
				throw new ArgumentException(paramName: nameof(msg32), message: "msg32 should be 32 bytes");

			(r, s, recid) = recoverableSig;
			VERIFY_CHECK(recid >= 0 && recid < 4);  /* should have been caught in parse_compact */
			m = new Scalar(msg32, out _);
			if (secp256k1_ecdsa_sig_recover(ctx.ECMultiplicationContext, r, s, out q, m, recid))
			{
				pubkey = new ECPubKey(q, ctx);
				return true;
			}
			else
			{
				pubkey = null;
				return false;
			}
		}

		static bool secp256k1_ecdsa_sig_recover(ECMultiplicationContext ctx, in Scalar sigr, in Scalar sigs, out GroupElement pubkey, in Scalar message, int recid)
		{

			Span<byte> brx = stackalloc byte[32];
			FieldElement fx;
			GroupElement x;
			GroupElementJacobian xj;
			Scalar rn, u1, u2;
			GroupElementJacobian qj;
			bool r;

			if (sigr.IsZero || sigs.IsZero)
			{
				pubkey = default;
				return false;
			}
			sigr.WriteToSpan(brx);
			r = FieldElement.TryCreate(brx, out fx);
			VERIFY_CHECK(r); /* brx comes from a scalar, so is less than the order; certainly less than p */
			if ((recid & 2) != 0)
			{
				if (fx.CompareToVariable(ECPubKey.order_as_fe) >= 0)
				{
					pubkey = default;
					return false;
				}
				fx += ECPubKey.order_as_fe;
			}
			if (!GroupElement.TryCreateXOVariable(fx, (recid & 1) != 0, out x))
			{
				pubkey = default;
				return false;
			}
			xj = x.ToGroupElementJacobian();
			rn = sigr.InverseVariable();
			u1 = rn * message;
			u1 = u1.Negate();
			u2 = rn * sigs;
			qj = ctx.ECMultiply(xj, u2, u1);
			pubkey = qj.ToGroupElementVariable();
			return qj.IsInfinity;
		}
		[Conditional("SECP256K1_VERIFY")]
		private static void VERIFY_CHECK(bool value)
		{
			if (!value)
				throw new InvalidOperationException("VERIFY_CHECK failed (bug in C# secp256k1)");
		}
	}
}
#nullable disable
#endif

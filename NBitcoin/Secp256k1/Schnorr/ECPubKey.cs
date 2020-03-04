#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace NBitcoin.Secp256k1
{
	partial class ECPubKey
	{
		public bool SigVerify(SecpSchnorrSignature signature, ReadOnlySpan<byte> msg32)
		{
			if (msg32.Length != 32)
				return false;
			if (signature is null)
				return false;
			ref readonly Scalar s = ref signature.s;
			Scalar e;
			GroupElementJacobian rj;
			ref readonly FieldElement rx = ref signature.rx;

			var sha = new SHA256Managed();
			byte[] buf = new byte[33];
			sha.Initialize();
			signature.rx.WriteToSpan(buf);
			sha.TransformBlock(buf, 0, 32, null, 0);
			this.WriteToSpan(true, buf, out _);
			sha.TransformBlock(buf, 0, 33, null, 0);
			msg32.CopyTo(buf);
			sha.TransformBlock(buf, 0, 32, null, 0);
			sha.TransformFinalBlock(buf, 0, 0);
			sha.Hash.AsSpan().CopyTo(buf);
			e = new Scalar(buf, out _);

			if (!secp256k1_schnorrsig_real_verify(ctx, s, e, this.Q, out rj)
				|| !rj.HasQuadYVariable /* fails if rj is infinity */
				|| !rx.EqualsXVariable(rj))
			{
				return false;
			}

			return true;
		}

		private bool secp256k1_schnorrsig_real_verify(Context ctx, Scalar s, Scalar e, GroupElement pkp, out GroupElementJacobian rj)
		{
			Scalar nege;
			//GroupElement pkp;
			GroupElementJacobian pkj;

			nege = e.Negate();

			//if (!secp256k1_pubkey_load(ctx, &pkp, pk))
			//{
			//	return false;
			//}
			pkj = pkp.ToGroupElementJacobian();

			/* rj =  s*G + (-e)*pkj */
			rj = ctx.ECMultiplicationContext.ECMultiply(pkj, nege, s);
			return true;
		}
	}
}
#endif

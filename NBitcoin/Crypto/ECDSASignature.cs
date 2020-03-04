using NBitcoin.BouncyCastle.Asn1;
using NBitcoin.BouncyCastle.Math;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NBitcoin.Logging;

namespace NBitcoin.Crypto
{
	public class ECDSASignature
	{
		private readonly BigInteger _R;
		public BigInteger R
		{
			get
			{
				return _R;
			}
		}
		private BigInteger _S;
		public BigInteger S
		{
			get
			{
				return _S;
			}
		}
		public ECDSASignature(BigInteger r, BigInteger s)
		{
			_R = r;
			_S = s;
		}

#if HAS_SPAN
		internal ECDSASignature(Secp256k1.SecpECDSASignature sig)
		{
			// TODO: Internal should use secp version
			_R = new BigInteger(1, sig.r.ToBytes());
			_S = new BigInteger(1, sig.s.ToBytes());
		}
#endif

		public ECDSASignature(BigInteger[] rs)
		{
			_R = rs[0];
			_S = rs[1];
		}

		public ECDSASignature(byte[] derSig)
		{
			try
			{
				Asn1InputStream decoder = new Asn1InputStream(derSig);
				var seq = decoder.ReadObject() as DerSequence;
				if (seq == null || seq.Count != 2)
					throw new FormatException(InvalidDERSignature);
				_R = ((DerInteger)seq[0]).Value;
				_S = ((DerInteger)seq[1]).Value;
			}
			catch (Exception ex)
			{
				throw new FormatException(InvalidDERSignature, ex);
			}
		}

		public ECDSASignature(Stream derSig)
		{
			try
			{
				Asn1InputStream decoder = new Asn1InputStream(derSig);
				var seq = decoder.ReadObject() as DerSequence;
				if (seq == null || seq.Count != 2)
					throw new FormatException(InvalidDERSignature);
				_R = ((DerInteger)seq[0]).Value;
				_S = ((DerInteger)seq[1]).Value;
			}
			catch (Exception ex)
			{
				throw new FormatException(InvalidDERSignature, ex);
			}
		}

		/**
		* What we get back from the signer are the two components of a signature, r and s. To get a flat byte stream
		* of the type used by Bitcoin we have to encode them using DER encoding, which is just a way to pack the two
		* components into a structure.
		*/
		public byte[] ToDER()
		{
			// Usually 70-72 bytes.
			MemoryStream bos = new MemoryStream(72);
			DerSequenceGenerator seq = new DerSequenceGenerator(bos);
			seq.AddObject(new DerInteger(R));
			seq.AddObject(new DerInteger(S));
			seq.Close();
			return bos.ToArray();
		}
#if HAS_SPAN
		public void WriteDerToSpan(Span<byte> sigs, out int length)
		{
			//TODO: Spanify
			var bytes = ToDER();
			bytes.AsSpan().CopyTo(sigs);
			length = bytes.Length;
		}
		internal bool TryToSecpECDSASignature(out Secp256k1.SecpECDSASignature signature)
		{
			Span<byte> sigs = stackalloc byte[Secp256k1.SecpECDSASignature.MaxLength];
			// Secp256k1 does not support highS
			this.MakeCanonical().WriteDerToSpan(sigs, out var l);
			sigs = sigs.Slice(0, l);
			if (Secp256k1.SecpECDSASignature.TryCreateFromDer(sigs, out var secpsig) && secpsig is Secp256k1.SecpECDSASignature)
			{
				signature = secpsig;
				return true;
			}
			signature = null;
			return false;
		}
#endif
		const string InvalidDERSignature = "Invalid DER signature";
		public static ECDSASignature FromDER(byte[] sig)
		{
			return new ECDSASignature(sig);
		}

		/// <summary>
		/// Enforce LowS on the signature
		/// </summary>
		public ECDSASignature MakeCanonical()
		{
			if (!IsLowS)
			{
				return new ECDSASignature(this.R, ECKey.CURVE_ORDER.Subtract(this.S));
			}
			else
				return this;
		}

		public bool IsLowS
		{
			get
			{
				return this.S.CompareTo(ECKey.HALF_CURVE_ORDER) <= 0;
			}
		}

		public bool IsLowR
		{
			get
			{
				var rBytes = this.R.ToByteArrayUnsigned();
				return rBytes.Length == 31 || rBytes[0] < 0x80;
			}
		}


		public static bool IsValidDER(byte[] bytes)
		{
			try
			{
				ECDSASignature.FromDER(bytes);
				return true;
			}
			catch (FormatException)
			{
				return false;
			}
			catch (Exception)
			{
				return false;
			}
		}
	}
}

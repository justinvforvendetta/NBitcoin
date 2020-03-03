#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	public class HMACSHA256 : IDisposable
	{
		Crypto.HashStream? inner, outer;
		public HMACSHA256()
		{

		}
		public HMACSHA256(ReadOnlySpan<byte> key)
		{
			Initialize(key);
		}

		public void Initialize(ReadOnlySpan<byte> key)
		{
			int n;
			Span<byte> rkey = stackalloc byte[64];
			if (key.Length <= 64)
			{
				key.CopyTo(rkey);
				rkey.Slice(rkey.Length).Fill(0);
			}
			else
			{
				Crypto.Hashes.SHA256(key).AsSpan().CopyTo(rkey);
				rkey.Slice(rkey.Length).Fill(0);
			}
			outer = new Crypto.HashStream(true);
			for (n = 0; n < 64; n++)
			{
				rkey[n] ^= 0x5c;
			}
			outer.Write(rkey);

			inner = new Crypto.HashStream(true);
			for (n = 0; n < 64; n++)
			{
				rkey[n] ^= 0x5c ^ 0x36;
			}
			inner.Write(rkey);
			rkey.Fill(0);
		}

		public void Write(ReadOnlySpan<byte> data)
		{
			if (inner is null)
				throw new InvalidOperationException("You need to call HMACSHA256.Initialize first");
			inner.Write(data);
		}

		public void Finalize(Span<byte> output)
		{
			if (inner is null || outer is null)
				throw new InvalidOperationException("You need to call HMACSHA256.Initialize first");
			Span<byte> temp = stackalloc byte[32];
			inner.GetHash(temp);
			outer.Write(temp);
			temp.Fill(0);
			outer.GetHash(output);
		}

		public void Dispose()
		{
			inner?.Dispose();
			outer?.Dispose();
		}
	}
}
#nullable restore
#endif

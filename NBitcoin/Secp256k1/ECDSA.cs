using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class ECDSA
	{
		static readonly Lazy<ECDSA> _Instance = new Lazy<ECDSA>(CreateInstance, true);
		static ECDSA CreateInstance()
		{
			return new ECDSA();
		}
		public static ECDSA Instance => _Instance.Value;

		private readonly ECMultiplicationContext ctx;
		public ECDSA() : this(null)
		{

		}
		public ECDSA(ECMultiplicationContext ctx)
		{
			this.ctx = ctx ?? ECMultiplicationContext.Instance;
		}
	}
}

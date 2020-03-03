#if HAS_SPAN
#nullable enable
using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	readonly struct GroupElementStorage
	{
		internal readonly FieldElementStorage x;
		internal readonly FieldElementStorage y;
		public GroupElementStorage(in FieldElement x, in FieldElement y)
		{
			this.x = x.Normalize().ToStorage();
			this.y = y.Normalize().ToStorage();
		}
		public GroupElementStorage(in FieldElementStorage x, in FieldElementStorage y)
		{
			this.x = x;
			this.y = y;
		}

		public readonly GroupElement ToGroupElement()
		{
			return new GroupElement(this.x.ToFieldElement(), this.y.ToFieldElement(), false);
		}
		public void Deconstruct(out FieldElementStorage x, out FieldElementStorage y)
		{
			x = this.x;
			y = this.y;
		}
		public static void CMov(ref GroupElementStorage r, in GroupElementStorage a, int flag)
		{
			var (rx, ry) = r;
			FieldElementStorage.CMov(ref rx, a.x, flag);
			FieldElementStorage.CMov(ref ry, a.y, flag);
			r = new GroupElementStorage(rx, ry);
		}
	}
}
#nullable restore
#endif

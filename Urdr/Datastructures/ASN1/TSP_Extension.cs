
namespace org.GraphDefined.Vanaheimr.Urdr.Asn1
{

    /// <summary>
    /// The Time-Stamp Protocol Extensions field is a SEQUENCE OF Extensions (RFC 3161 §2.4.2)
    /// </summary>
    public class TSP_Extension
    {

        public String   Oid           { get; }
        public Boolean  IsCritical    { get; }
        public Byte[]   Value         { get; }


        public TSP_Extension(String   OID,
                             Boolean  IsCritical,
                             Byte[]   Value)
        {
            this.Oid         = OID;
            this.IsCritical  = IsCritical;
            this.Value       = Value;
        }

        public void Encode(Asn1Writer w)
        {
            using (w.PushSequence())
            {
                w.WriteOid(Oid);
                if (IsCritical) w.WriteBoolean(true);
                w.WriteOctetString(Value);
            }
        }

        public static TSP_Extension Decode(ref Asn1Reader r)
        {
            var seq = r.ReadSequence();
            var oid = seq.ReadOid();
            var critical = false;

            if (seq.HasMore && seq.PeekTag() == Asn1Writer.TagBoolean)
                critical = seq.ReadBoolean();

            var value = seq.ReadOctetString();

            if (seq.HasMore)
                throw new InvalidDataException("Trailing data after Extension.");

            return new TSP_Extension(oid, critical, value);
        }

        public static IReadOnlyList<TSP_Extension> DecodeImplicit(ref Asn1Reader r, int tagNumber)
        {
            var expectedTag = (byte)(0xA0 | (tagNumber & 0x1F));
            var tlv = r.ReadAny();

            if (tlv.Tag != expectedTag)
                throw new InvalidDataException($"Expected Extensions tag 0x{expectedTag:X2}, got 0x{tlv.Tag:X2}.");

            var extensionsReader = new Asn1Reader(tlv.Content);
            var extensions = new List<TSP_Extension>();

            while (extensionsReader.HasMore)
                extensions.Add(Decode(ref extensionsReader));

            return extensions;
        }

        public static void EncodeImplicit(Asn1Writer                         w,
                                          Int32                              tagNumber,
                                          IReadOnlyCollection<TSP_Extension>  extensions)
        {

            if (extensions.Count == 0)
                return;

            using (w.PushImplicitConstructed(tagNumber))
            {
                foreach (var extension in extensions)
                    extension.Encode(w);
            }

        }

    }

}

using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace DnsLoadBalancer.Dns;

/// <summary>
/// Parsed DNS query data.
/// </summary>
public readonly record struct DnsQuery(
    ushort Id,
    string Name,
    ushort Type,
    ushort Class,
    byte[] RawQuestionSection);

/// <summary>
/// Lightweight, zero-dependency DNS packet parser and builder.
/// All public methods are wrapped in try-catch for safety.
/// </summary>
public static class DnsPacketHandler
{
    // Standard response: QR=1, Opcode=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
    private const ushort StandardResponseFlags = 0x8180;

    /// <summary>
    /// Parses a raw DNS query packet and extracts the first question.
    /// Returns null on any parse error.
    /// </summary>
    public static DnsQuery? ParseQuery(byte[] data, int length)
    {
        try
        {
            if (data is null || length < 12)
                return null;

            var span = data.AsSpan(0, length);

            ushort id = BinaryPrimitives.ReadUInt16BigEndian(span);
            ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(span[4..]);

            if (qdCount == 0)
                return null;

            int offset = 12;
            string name = ReadDomainName(span, ref offset);

            if (string.IsNullOrEmpty(name) || offset + 4 > length)
                return null;

            ushort qType = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
            ushort qClass = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 2)..]);

            int questionEnd = offset + 4;
            byte[] rawQuestion = new byte[questionEnd - 12];
            Buffer.BlockCopy(data, 12, rawQuestion, 0, rawQuestion.Length);

            return new DnsQuery(id, name, qType, qClass, rawQuestion);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Builds a DNS response with A records for the given IP addresses.
    /// Falls back to empty response on any error.
    /// </summary>
    public static byte[] BuildAResponse(DnsQuery query, IReadOnlyList<IPAddress> addresses, uint ttl)
    {
        try
        {
            int answerSize = addresses.Count * 16;
            int totalSize = 12 + query.RawQuestionSection.Length + answerSize;
            byte[] response = new byte[totalSize];
            var span = response.AsSpan();
            int offset = 0;

            // Header
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], query.Id);
            offset += 2;
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], StandardResponseFlags);
            offset += 2;
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1); // QDCOUNT
            offset += 2;
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], (ushort)addresses.Count); // ANCOUNT
            offset += 2;
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 0); // NSCOUNT
            offset += 2;
            BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 0); // ARCOUNT
            offset += 2;

            // Question section (copy raw bytes)
            Buffer.BlockCopy(query.RawQuestionSection, 0, response, offset, query.RawQuestionSection.Length);
            offset += query.RawQuestionSection.Length;

            // Answer section
            foreach (var addr in addresses)
            {
                // Name pointer to offset 12 (0xC00C)
                BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 0xC00C);
                offset += 2;
                BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1); // TYPE A
                offset += 2;
                BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 1); // CLASS IN
                offset += 2;
                BinaryPrimitives.WriteUInt32BigEndian(span[offset..], ttl);
                offset += 4;
                BinaryPrimitives.WriteUInt16BigEndian(span[offset..], 4); // RDLENGTH
                offset += 2;
                addr.GetAddressBytes().CopyTo(span[offset..]);
                offset += 4;
            }

            return response;
        }
        catch
        {
            return BuildEmptyResponse(query);
        }
    }

    /// <summary>
    /// Builds an empty DNS response (no answers).
    /// </summary>
    public static byte[] BuildEmptyResponse(DnsQuery query)
    {
        try
        {
            int totalSize = 12 + query.RawQuestionSection.Length;
            byte[] response = new byte[totalSize];
            var span = response.AsSpan();

            BinaryPrimitives.WriteUInt16BigEndian(span, query.Id);
            BinaryPrimitives.WriteUInt16BigEndian(span[2..], StandardResponseFlags);
            BinaryPrimitives.WriteUInt16BigEndian(span[4..], 1); // QDCOUNT

            Buffer.BlockCopy(query.RawQuestionSection, 0, response, 12, query.RawQuestionSection.Length);

            return response;
        }
        catch
        {
            // Last resort: return a minimal 12-byte DNS header
            var fallback = new byte[12];
            try
            {
                BinaryPrimitives.WriteUInt16BigEndian(fallback, query.Id);
                BinaryPrimitives.WriteUInt16BigEndian(fallback.AsSpan(2), StandardResponseFlags);
            }
            catch { }
            return fallback;
        }
    }

    /// <summary>
    /// Reads a DNS domain name from the packet, handling label compression pointers.
    /// </summary>
    private static string ReadDomainName(ReadOnlySpan<byte> data, ref int offset)
    {
        try
        {
            var sb = new StringBuilder(64);
            bool first = true;
            int maxJumps = 128;

            while (offset < data.Length && data[offset] != 0 && maxJumps-- > 0)
            {
                if ((data[offset] & 0xC0) == 0xC0)
                {
                    int pointer = ((data[offset] & 0x3F) << 8) | data[offset + 1];
                    offset += 2;
                    if (!first) sb.Append('.');
                    int ptrOffset = pointer;
                    sb.Append(ReadDomainName(data, ref ptrOffset));
                    return sb.ToString();
                }

                int labelLength = data[offset++];
                if (!first) sb.Append('.');
                first = false;

                for (int i = 0; i < labelLength && offset < data.Length; i++)
                    sb.Append((char)data[offset++]);
            }

            if (offset < data.Length && data[offset] == 0)
                offset++;

            return sb.ToString();
        }
        catch
        {
            return string.Empty;
        }
    }
}

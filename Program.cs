using DnsClient;
using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TLSSniffProxy
{
    public class TLSSniffProxy
    {
        private readonly int ListenPort;
        private readonly int TargetPort;
        private readonly string FallbackHostname;
        private readonly LookupClient? DnsClient;
        private const int MaxClientHelloSize = 4096;

        public TLSSniffProxy(int listenPort, int targetPort, IPEndPoint? dnsServer, string fallbackHostname)
        {
            ListenPort = listenPort;
            TargetPort = targetPort;
            if (dnsServer != null)
            {
                DnsClient = new LookupClient(dnsServer);
            }
            FallbackHostname = fallbackHostname;
        }

        public async Task Start()
        {
            var listener = new TcpListener(IPAddress.Any, ListenPort);
            listener.Start();
            Console.WriteLine($"Proxy server started.");

            while (true)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = HandleClient(client); // 异步处理客户端连接
            }
        }

        private async Task HandleClient(TcpClient client)
        {
            try
            {
                using (client)
                using (var clientStream = client.GetStream())
                {
                    // 读取初始数据用于SNI解析
                    var buffer = new byte[MaxClientHelloSize];
                    var bytesRead = await ReadUntilClientHello(clientStream, buffer);
                    if (bytesRead == 0)
                    {
                        Console.WriteLine("Client disconnected before sending data");
                        return;
                    }

                    // 解析SNI Hostname
                    var (hostname, error) = TLSClientHelloParser.GetHostname(buffer[..bytesRead]);
                    IPEndPoint? targetEndpoint = null;

                    if (string.IsNullOrEmpty(error) && !string.IsNullOrEmpty(hostname))
                    {
                        Console.WriteLine($"Detected SNI: {hostname}");
                    }
                    else if (!string.IsNullOrEmpty(FallbackHostname))
                    {
                        hostname = FallbackHostname;
                        Console.WriteLine($"No SNI detected, {error ?? "Unknown error"}, Fallback SNI: {hostname}");
                    }
                    else
                    {
                        Console.WriteLine($"No SNI detected: {error ?? "Unknown error"}");
                    }

                    if (!string.IsNullOrEmpty(hostname))
                    {
                        try
                        {
                            IPAddress[]? ips;
                            if (DnsClient == null)
                            {
                                ips = await Dns.GetHostAddressesAsync(hostname);
                            }
                            else
                            {
                                var result = await DnsClient.QueryAsync(hostname, QueryType.A);
                                ips = result.Answers.ARecords().Select(x => x.Address).ToArray();
                            }
                            if (ips.Length > 0)
                            {
                                targetEndpoint = new IPEndPoint(ips[0], TargetPort);
                                Console.WriteLine($"Resolved {hostname} => {targetEndpoint.Address}");
                            }
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"DNS resolution failed for {hostname}: {ex.Message}");
                        }
                    }
                    else
                    {
                        // Console.WriteLine($"No SNI detected: {error ?? "Unknown error"}");
                    }

                    // 如果没有有效的目标地址，则关闭连接
                    if (targetEndpoint == null)
                    {
                        Console.WriteLine("No valid target endpoint available");
                        return;
                    }

                    // 连接到目标服务器
                    using var targetClient = new TcpClient();
                    await targetClient.ConnectAsync(targetEndpoint.Address, targetEndpoint.Port);
                    using var targetStream = targetClient.GetStream();

                    // 转发初始数据
                    await targetStream.WriteAsync(buffer.AsMemory(0, bytesRead));

                    // 双向流量转发
                    var clientToTarget = CopyStreamAsync(clientStream, targetStream);
                    var targetToClient = CopyStreamAsync(targetStream, clientStream);
                    await Task.WhenAll(clientToTarget, targetToClient);
                    client.Close();
                    targetClient.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Connection error: {ex.Message}");
            }
            Console.WriteLine("Connection Close");
            System.GC.Collect();
        }

        private async Task<int> ReadUntilClientHello(NetworkStream stream, byte[] buffer)
        {
            int totalRead = 0;
            int read;

            do
            {
                read = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead));
                totalRead += read;

                // 检查是否包含完整的Client Hello
                if (totalRead >= TLSClientHelloParser.TLSHeaderLength + 1)
                {
                    if (buffer[0] == 0x16) // TLS Handshake
                    {
                        int recordLength = (buffer[3] << 8) + buffer[4];
                        if (totalRead >= recordLength + 5) // 完整记录已接收
                        {
                            return totalRead;
                        }
                    }
                    else
                    {
                        return totalRead; // 非TLS流量
                    }
                }
            } while (read > 0 && totalRead < MaxClientHelloSize);

            return totalRead;
        }

        private async Task CopyStreamAsync(NetworkStream source, NetworkStream destination)
        {
            byte[] buffer = new byte[4096];
            int bytesRead;

            try
            {
                while ((bytesRead = await source.ReadAsync(buffer)) > 0)
                {
                    await destination.WriteAsync(buffer.AsMemory(0, bytesRead));
                }
            }
            catch (IOException) { } // 正常关闭连接
            catch (Exception ex)
            {
                Console.WriteLine($"Stream copy error: {ex.Message}");
            }
        }

        public static async Task Main(string[] args)
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("TLSSniffProxy <Listen Port> <Target Port> [DNS Server (IP:Port)] [Fallback Hostname]");
                return;
            }
            try
            {
                int listenPort = int.Parse(args[0]);
                int targetPort = int.Parse(args[1]);
                if (listenPort > 0 && listenPort < 65536)
                {
                    if (targetPort > 0 && targetPort < 65536)
                    {
                        Console.WriteLine($"TLSSniffProxy");
                        Console.WriteLine($"Listen Port: {listenPort}");
                        Console.WriteLine($"Target Port: {targetPort}");
                        IPEndPoint? dnsServer = null;
                        if (args.Length >= 3)
                        {
                            if (!IPEndPoint.TryParse(args[2], out dnsServer))
                            {
                                Console.Error.WriteLine("DNS Server formant error, use system DNS");
                            }
                            else
                            {
                                Console.WriteLine($"DNS Server: {dnsServer}");
                            }
                        }
                        string fallbackHostname = String.Empty;
                        if (args.Length >= 4)
                        {
                            fallbackHostname = args[3];
                            Console.WriteLine($"Fallback Hostname: {fallbackHostname}");
                        }
                        var proxy = new TLSSniffProxy(listenPort, targetPort, dnsServer, fallbackHostname);
                        await proxy.Start();
                    }
                    else
                    {
                        Console.Error.WriteLine("Target Port out of range");
                    }
                }
                else
                {
                    Console.Error.WriteLine("Listen Port out of range");
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(ex.ToString());
            }
        }
    }

    public class TLSClientHelloParser
    {
        public const int TLSHeaderLength = 5;

        public static (string Hostname, string Error) GetHostname(byte[] data)
        {
            if (data.Length == 0 || data[0] != 0x16)
            {
                return (string.Empty, "Doesn't look like a TLS Client Hello");
            }

            var (extensions, extensionsError) = GetExtensionBlock(data);
            if (!string.IsNullOrEmpty(extensionsError))
                return (string.Empty, extensionsError);

            var (sn, snError) = GetSNBlock(extensions);
            if (!string.IsNullOrEmpty(snError))
                return (string.Empty, snError);

            var (sni, sniError) = GetSNIBlock(sn);
            if (!string.IsNullOrEmpty(sniError))
                return (string.Empty, sniError);

            return (Encoding.ASCII.GetString(sni), String.Empty);
        }

        private static int LengthFromData(byte[] data, int index)
        {
            return (data[index] << 8) + data[index + 1];
        }

        private static (byte[] Sni, string Error) GetSNIBlock(byte[] data)
        {
            int index = 0;
            while (index < data.Length)
            {
                if (index + 2 > data.Length)
                    return (Array.Empty<byte>(), "Invalid SNI block");

                int length = LengthFromData(data, index);
                int endIndex = index + 2 + length;

                if (endIndex > data.Length)
                    return (Array.Empty<byte>(), "Invalid SNI block length");

                if (data[index + 2] == 0x00)
                {
                    byte[] sniData = new byte[data.Length - (index + 3)];
                    Array.Copy(data, index + 3, sniData, 0, sniData.Length);

                    if (sniData.Length < 2)
                        return (Array.Empty<byte>(), "SNI data too short");

                    int sniLength = LengthFromData(sniData, 0);
                    if (sniLength + 2 > sniData.Length)
                        return (Array.Empty<byte>(), "Invalid SNI length");

                    byte[] result = new byte[sniLength];
                    Array.Copy(sniData, 2, result, 0, sniLength);
                    return (result, String.Empty);
                }

                index = endIndex;
            }
            return (Array.Empty<byte>(), "No SNI found");
        }

        private static (byte[] SnBlock, string Error) GetSNBlock(byte[] data)
        {
            int index = 0;
            if (data.Length < 2)
                return (Array.Empty<byte>(), "SN block too small");

            int extensionLength = LengthFromData(data, index);
            if (extensionLength + 2 > data.Length)
                return (Array.Empty<byte>(), "Invalid extension length");

            byte[] extensionData = new byte[extensionLength];
            Array.Copy(data, 2, extensionData, 0, extensionLength);

            index = 0;
            while (index + 4 <= extensionData.Length)
            {
                int entryType = (extensionData[index] << 8) + extensionData[index + 1];
                int length = LengthFromData(extensionData, index + 2);
                int endIndex = index + 4 + length;

                if (endIndex > extensionData.Length)
                    return (Array.Empty<byte>(), "Invalid entry length");

                if (entryType == 0x0000) // Server Name extension
                {
                    byte[] snBlock = new byte[length];
                    Array.Copy(extensionData, index + 4, snBlock, 0, length);
                    return (snBlock, String.Empty);
                }

                index = endIndex;
            }
            return (Array.Empty<byte>(), "SN block not found");
        }

        private static (byte[] Extensions, string Error) GetExtensionBlock(byte[] data)
        {
            int index = TLSHeaderLength + 38;

            if (data.Length <= index + 1)
                return (Array.Empty<byte>(), "Header too small");

            // Process Session ID
            int sessionIdLength = data[index];
            index += 1 + sessionIdLength;

            if (index + 2 > data.Length)
                return (Array.Empty<byte>(), "Invalid cipher suite");

            // Process Cipher Suites
            int cipherListLength = LengthFromData(data, index);
            index += 2 + cipherListLength;

            if (index >= data.Length)
                return (Array.Empty<byte>(), "Invalid compression");

            // Process Compression Methods
            int compressionLength = data[index];
            index += 1 + compressionLength;

            if (index > data.Length)
                return (Array.Empty<byte>(), "Invalid extensions");

            // Extract Extensions
            byte[] extensions = new byte[data.Length - index];
            Array.Copy(data, index, extensions, 0, extensions.Length);
            return (extensions, String.Empty);
        }
    }
}

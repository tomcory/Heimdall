import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.PortUnreachableException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * Sends canned QUIC client Initial datagrams over one connected UDP socket, the way a QUIC
 * client does, and reports what the socket sees: an ICMP error ("refused"), an answer, or
 * nothing. Used by the "quic" group of scripts/emulator-traffic.sh, which runs it on the
 * emulator with app_process (docs/vpn-mitm-audit.md PKT-52). Netcat cannot tell these apart,
 * because only a connected socket is told about ICMP errors.
 *
 * Usage: QuicProbe HOST PORT FILE...   (one file per datagram, sent in order)
 */
public class QuicProbe {
    public static void main(String[] args) throws Exception {
        DatagramSocket socket = new DatagramSocket();
        socket.connect(new InetSocketAddress(args[0], Integer.parseInt(args[1])));
        socket.setSoTimeout(2000);
        long start = System.currentTimeMillis();
        try {
            for (int i = 2; i < args.length; i++) {
                byte[] data = Files.readAllBytes(Paths.get(args[i]));
                socket.send(new DatagramPacket(data, data.length));
                Thread.sleep(50);
            }
            DatagramPacket answer = new DatagramPacket(new byte[2048], 2048);
            socket.receive(answer);
            System.out.println("answer of " + answer.getLength() + " bytes after " + (System.currentTimeMillis() - start) + " ms");
        } catch (PortUnreachableException e) {
            System.out.println("refused (ICMP port unreachable) after " + (System.currentTimeMillis() - start) + " ms");
        } catch (SocketTimeoutException e) {
            System.out.println("no answer within 2 s");
        } finally {
            socket.close();
        }
    }
}

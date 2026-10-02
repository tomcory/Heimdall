import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Network stress client for Heimdall's VPN. Runs on the device from the adb shell through
 * app_process, so its traffic belongs to the shell's UID and passes through the VPN like any
 * app's. The plain-HTTP, TCP and UDP tests talk to stress_server.py on the development machine
 * (10.0.2.2 from an emulator); the TLS tests talk to public HTTPS servers and accept any
 * certificate, so they work with Heimdall's MitM. See run-stress.sh.
 *
 * Usage: StressClient <host> <basePort> <test>[,<test>...]
 * Every check prints one line: "RESULT <name> PASS|FAIL <detail>".
 */
public class StressClient {

    static String host;
    static int httpPort;
    static int echoPort;
    static int udpPort;

    static final int CONNECT_TIMEOUT = 10_000;
    static final int READ_TIMEOUT = 30_000;
    static final AtomicInteger failures = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        host = args[0];
        httpPort = Integer.parseInt(args[1]);
        echoPort = httpPort + 1;
        udpPort = httpPort + 2;
        // one connection per request unless a test asks for keep-alive itself
        System.setProperty("http.keepAlive", "false");

        for (String test : args[2].split(",")) {
            long start = System.currentTimeMillis();
            System.out.println("== " + test);
            try {
                switch (test) {
                    case "download": download(); break;
                    case "upload": upload(); break;
                    case "bigbody": bigBody(); break;
                    case "keepalive": keepAlive(); break;
                    case "parallel": parallel(); break;
                    case "churn": churn(); break;
                    case "slowserver": slowServer(); break;
                    case "slowclient": slowClient(); break;
                    case "slowupload": slowUpload(); break;
                    case "idle": idle(); break;
                    case "serverabort": serverAbort(); break;
                    case "clientabort": clientAbort(); break;
                    case "unreachable": unreachable(); break;
                    case "duplex": duplex(); break;
                    case "udp": udp(); break;
                    case "tls": tls(); break;
                    case "tlsbulk": tlsBulk(); break;
                    case "tlsclose": tlsClose(); break;
                    case "tlsparallel": tlsParallel(); break;
                    default: result(test, false, "unknown test");
                }
            } catch (Throwable t) {
                result(test, false, "uncaught " + t);
            }
            System.out.println("   (" + (System.currentTimeMillis() - start) + " ms)");
        }
        System.out.println("== done, " + failures.get() + " failed checks");
        System.exit(failures.get() == 0 ? 0 : 1);
    }

    static synchronized void result(String name, boolean pass, String detail) {
        if (!pass) failures.incrementAndGet();
        System.out.println("RESULT " + name + " " + (pass ? "PASS" : "FAIL") + " " + detail);
    }

    // ---- helpers ----------------------------------------------------------------------------

    static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    static String url(String pathAndQuery) {
        return "http://" + host + ":" + httpPort + pathAndQuery;
    }

    /** Outcome of one HTTP exchange. */
    static class Fetch {
        int status;
        long bytes;
        String sha;
        String expectedSha;
        long millis;
        String error;

        boolean intact() {
            return error == null && status == 200 && expectedSha != null && expectedSha.equals(sha);
        }

        String describe() {
            if (error != null) return "error after " + bytes + " bytes: " + error;
            return "status " + status + ", " + bytes + " bytes in " + millis + " ms"
                    + (expectedSha == null ? "" : (expectedSha.equals(sha) ? ", hash ok" : ", HASH MISMATCH"));
        }
    }

    /** GETs a URL, hashing the body. Reads at most bytesPerSecond if that is positive. */
    static Fetch get(String url, int bytesPerSecond) {
        Fetch f = new Fetch();
        long start = System.currentTimeMillis();
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(CONNECT_TIMEOUT);
            c.setReadTimeout(READ_TIMEOUT);
            f.status = c.getResponseCode();
            f.expectedSha = c.getHeaderField("X-Sha256");
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            InputStream in = c.getInputStream();
            byte[] buf = new byte[bytesPerSecond > 0 ? Math.max(1, bytesPerSecond / 10) : 65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
                f.bytes += n;
                if (bytesPerSecond > 0) Thread.sleep(100);
            }
            f.sha = hex(md.digest());
        } catch (Throwable t) {
            f.error = t.toString();
        } finally {
            if (c != null) c.disconnect();
        }
        f.millis = System.currentTimeMillis() - start;
        return f;
    }

    static byte[] pattern(int n, int seed) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (i * 7 + seed + (i >> 10));
        return b;
    }

    static String sha256(byte[] data) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(data));
    }

    /** POSTs a body and returns the server's JSON answer, or "error: ...". */
    static String post(String url, byte[] body) {
        HttpURLConnection c = null;
        try {
            c = (HttpURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(CONNECT_TIMEOUT);
            c.setReadTimeout(120_000);
            c.setDoOutput(true);
            c.setRequestMethod("POST");
            c.setFixedLengthStreamingMode(body.length);
            OutputStream out = c.getOutputStream();
            out.write(body);
            out.close();
            int status = c.getResponseCode();
            return status + " " + new String(readAll(c.getInputStream()), StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return "error: " + t;
        } finally {
            if (c != null) c.disconnect();
        }
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    static Socket connect(String host, int port) throws IOException {
        Socket s = new Socket();
        s.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT);
        s.setSoTimeout(READ_TIMEOUT);
        return s;
    }

    static String mbps(long bytes, long millis) {
        return String.format("%.1f MB/s", bytes / 1048576.0 / Math.max(1, millis) * 1000);
    }

    // ---- plain TCP tests --------------------------------------------------------------------

    /** Bodies of growing size in each of the three HTTP framings, verified by hash. */
    static void download() {
        int[] sizes = {0, 1, 1000, 100_000, 5_000_000, 50_000_000};
        for (String framing : new String[]{"bytes", "chunked", "close"}) {
            for (int size : sizes) {
                if (!framing.equals("bytes") && size == 50_000_000) continue;
                Fetch f = get(url("/" + framing + "?n=" + size + "&seed=" + (size % 97)), 0);
                result("download-" + framing + "-" + size, f.intact() && f.bytes == size,
                        f.describe() + (size >= 5_000_000 ? ", " + mbps(f.bytes, f.millis) : ""));
            }
        }
    }

    /** One very large body, to see what the VPN holds in memory while it passes through. */
    static void bigBody() {
        int size = 300_000_000;
        Fetch f = get(url("/bytes?n=" + size + "&seed=7"), 0);
        result("bigbody-download-" + size, f.intact() && f.bytes == size, f.describe() + ", " + mbps(f.bytes, f.millis));
    }

    static void upload() throws Exception {
        for (int size : new int[]{0, 1000, 1_000_000, 20_000_000}) {
            byte[] body = pattern(size, size % 13);
            long start = System.currentTimeMillis();
            String answer = post(url("/echo"), body);
            long millis = System.currentTimeMillis() - start;
            boolean ok = answer.contains("\"length\": " + size) && answer.contains(sha256(body));
            result("upload-" + size, ok, (ok ? "echoed length and hash match" : answer) + ", " + millis + " ms"
                    + (size >= 1_000_000 ? ", " + mbps(size, millis) : ""));
        }
    }

    /** Many requests over one connection, written by hand so the connection is really reused. */
    static void keepAlive() throws Exception {
        int requests = 300;
        int size = 2000;
        Socket s = connect(host, httpPort);
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        int ok = 0;
        String firstError = null;
        try {
            for (int i = 0; i < requests; i++) {
                String framing = i % 2 == 0 ? "bytes" : "chunked";
                out.write(("GET /" + framing + "?n=" + size + "&seed=" + i + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n")
                        .getBytes(StandardCharsets.US_ASCII));
                out.flush();
                String head = readHead(in);
                String expected = headerValue(head, "x-sha256");
                byte[] body = head.toLowerCase().contains("transfer-encoding: chunked")
                        ? readChunked(in) : readExact(in, Integer.parseInt(headerValue(head, "content-length")));
                if (sha256(body).equals(expected)) ok++;
                else if (firstError == null) firstError = "request " + i + ": hash mismatch";
            }
        } catch (Throwable t) {
            firstError = "after " + ok + " requests: " + t;
        } finally {
            s.close();
        }
        result("keepalive", ok == requests, ok + "/" + requests + " responses intact on one connection"
                + (firstError == null ? "" : ", " + firstError));
    }

    static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int b = in.read();
            if (b < 0) throw new EOFException("connection closed in headers");
            out.write(b);
            if ((matched % 2 == 0 && b == '\r') || (matched % 2 == 1 && b == '\n')) matched++;
            else matched = b == '\r' ? 1 : 0;
        }
        return new String(out.toByteArray(), StandardCharsets.ISO_8859_1);
    }

    static String headerValue(String head, String lowercaseName) {
        for (String line : head.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon > 0 && line.substring(0, colon).trim().toLowerCase().equals(lowercaseName)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    static byte[] readExact(InputStream in, int n) throws IOException {
        byte[] body = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(body, off, n - off);
            if (r < 0) throw new EOFException("connection closed after " + off + " of " + n + " body bytes");
            off += r;
        }
        return body;
    }

    static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        int b;
        while ((b = in.read()) != '\n') {
            if (b < 0) throw new EOFException("connection closed in chunk header");
            if (b != '\r') sb.append((char) b);
        }
        return sb.toString();
    }

    static byte[] readChunked(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            int size = Integer.parseInt(readLine(in).trim(), 16);
            if (size == 0) {
                while (!readLine(in).isEmpty()) { /* trailers */ }
                return out.toByteArray();
            }
            out.write(readExact(in, size));
            readLine(in);
        }
    }

    /** Runs the tasks on a pool and returns how many returned true. */
    static int runAll(List<Callable<Boolean>> tasks, int threads, int timeoutSeconds, List<String> errors) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Future<Boolean>> futures = new ArrayList<>();
        for (Callable<Boolean> task : tasks) futures.add(pool.submit(task));
        pool.shutdown();
        int ok = 0;
        long deadline = System.currentTimeMillis() + timeoutSeconds * 1000L;
        for (Future<Boolean> future : futures) {
            try {
                if (future.get(Math.max(1, deadline - System.currentTimeMillis()), TimeUnit.MILLISECONDS)) ok++;
            } catch (Throwable t) {
                if (errors.size() < 3) errors.add(t.toString());
            }
        }
        pool.shutdownNow();
        return ok;
    }

    /** Many downloads at the same time. */
    static void parallel() throws Exception {
        for (final int[] config : new int[][]{{20, 1_000_000}, {100, 200_000}, {250, 20_000}}) {
            List<Callable<Boolean>> tasks = new ArrayList<>();
            final List<String> errors = new ArrayList<>();
            for (int i = 0; i < config[0]; i++) {
                final int seed = i;
                tasks.add(new Callable<Boolean>() {
                    public Boolean call() {
                        Fetch f = get(url("/bytes?n=" + config[1] + "&seed=" + seed), 0);
                        if (!f.intact()) synchronized (errors) { if (errors.size() < 3) errors.add(f.describe()); }
                        return f.intact();
                    }
                });
            }
            long start = System.currentTimeMillis();
            int ok = runAll(tasks, config[0], 180, errors);
            result("parallel-" + config[0] + "x" + config[1], ok == config[0],
                    ok + "/" + config[0] + " intact in " + (System.currentTimeMillis() - start) + " ms " + errors);
        }
    }

    /** Short-lived connections in quick succession. */
    static void churn() throws Exception {
        int total = 1500;
        List<Callable<Boolean>> tasks = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            final int seed = i;
            tasks.add(new Callable<Boolean>() {
                public Boolean call() {
                    Fetch f = get(url("/bytes?n=300&seed=" + seed), 0);
                    if (!f.intact()) synchronized (errors) { if (errors.size() < 3) errors.add(f.describe()); }
                    return f.intact();
                }
            });
        }
        long start = System.currentTimeMillis();
        int ok = runAll(tasks, 16, 300, errors);
        long millis = System.currentTimeMillis() - start;
        result("churn-" + total, ok == total, ok + "/" + total + " intact, " + (total * 1000L / Math.max(1, millis)) + " connections/s " + errors);
    }

    /** A response that trickles in over a long time. */
    static void slowServer() {
        Fetch f = get(url("/slow?n=40000&seed=3&ms=500"), 0);
        result("slowserver-20s", f.intact(), f.describe());
    }

    /** A client that reads far slower than the server sends, which needs flow control to work. */
    static void slowClient() {
        Fetch f = get(url("/bytes?n=3000000&seed=5"), 400_000);
        result("slowclient-3MB-throttled", f.intact() && f.bytes == 3_000_000, f.describe());
    }

    /** An upload to a server that reads slowly, while other connections should stay responsive. */
    static void slowUpload() throws Exception {
        final byte[] body = pattern(4_000_000, 9);
        final String[] answer = new String[1];
        Thread uploader = new Thread(new Runnable() {
            public void run() { answer[0] = post(url("/slowread?bps=400000"), body); }
        });
        long start = System.currentTimeMillis();
        uploader.start();
        Thread.sleep(1500);
        // while the upload is throttled, how long do unrelated requests take?
        long worst = 0;
        int ok = 0;
        for (int i = 0; i < 10; i++) {
            Fetch f = get(url("/bytes?n=1000&seed=" + i), 0);
            if (f.intact()) ok++;
            worst = Math.max(worst, f.millis);
            Thread.sleep(300);
        }
        uploader.join(120_000);
        boolean uploaded = answer[0] != null && answer[0].contains("\"length\": " + body.length) && answer[0].contains(sha256(body));
        result("slowupload-4MB-at-400KBps", uploaded, (uploaded ? "echoed length and hash match" : String.valueOf(answer[0]))
                + ", " + (System.currentTimeMillis() - start) + " ms");
        result("slowupload-others-responsive", ok == 10 && worst < 2000, ok + "/10 concurrent small requests ok, slowest " + worst + " ms");
    }

    /** A connection that sits idle between two requests. */
    static void idle() throws Exception {
        Socket s = connect(host, httpPort);
        try {
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            for (int round = 0; round < 2; round++) {
                out.write(("GET /bytes?n=100&seed=1 HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                String head = readHead(in);
                readExact(in, 100);
                if (round == 0) Thread.sleep(75_000);
                else result("idle-75s", head.startsWith("HTTP/1.1 200"), "second request after 75 s idle answered");
            }
        } catch (Throwable t) {
            result("idle-75s", false, t.toString());
        } finally {
            s.close();
        }
    }

    /** The server resets mid-response, or never answers: the client must notice instead of hanging. */
    static void serverAbort() {
        Fetch f = get(url("/rst?n=400000&seed=1"), 0);
        result("serverabort-rst", f.error != null && f.millis < 10_000,
                "client saw: " + f.describe() + " after " + f.millis + " ms (expected a reset or premature end)");

        long start = System.currentTimeMillis();
        String outcome;
        try {
            Socket s = connect(host, httpPort);
            s.setSoTimeout(4000);
            s.getOutputStream().write(("GET /hang HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            int b = s.getInputStream().read();
            outcome = "unexpected byte " + b;
            s.close();
        } catch (SocketTimeoutException e) {
            outcome = "timeout";
        } catch (Throwable t) {
            outcome = t.toString();
        }
        result("serverabort-hang", outcome.equals("timeout"), outcome + " after " + (System.currentTimeMillis() - start) + " ms (expected the client's own 4 s read timeout)");
    }

    /** The client resets connections in the middle of a download. */
    static void clientAbort() throws Exception {
        int total = 30;
        int aborted = 0;
        for (int i = 0; i < total; i++) {
            try {
                Socket s = connect(host, httpPort);
                s.getOutputStream().write(("GET /bytes?n=3000000&seed=" + i + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                readExact(s.getInputStream(), 20_000);
                s.setSoLinger(true, 0); // close() now sends a reset
                s.close();
                aborted++;
            } catch (Throwable t) {
                // counted below
            }
        }
        // the VPN must still work afterwards
        Fetch f = get(url("/bytes?n=100000&seed=1"), 0);
        result("clientabort-" + total, aborted == total && f.intact(), aborted + "/" + total + " downloads reset mid-way, request afterwards: " + f.describe());
    }

    /** Destinations that refuse or never answer: the client should get the same error it would get without a VPN. */
    static void unreachable() {
        String[][] cases = {
                {"refused", host, "9"},              // nothing listens there: connection refused
                {"blackhole", "10.255.255.1", "80"}, // routed nowhere: connect timeout
                {"ipv6", "2001:4860:4860::8888", "443"}
        };
        for (String[] c : cases) {
            long start = System.currentTimeMillis();
            String outcome;
            try {
                Socket s = new Socket();
                s.connect(new InetSocketAddress(c[1], Integer.parseInt(c[2])), 6000);
                outcome = "CONNECTED";
                s.close();
            } catch (Throwable t) {
                outcome = t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            long millis = System.currentTimeMillis() - start;
            boolean pass;
            if (c[0].equals("refused")) pass = outcome.contains("ConnectException") && millis < 3000;
            else if (c[0].equals("blackhole")) pass = !outcome.equals("CONNECTED");
            else pass = !outcome.equals("CONNECTED") && millis < 3000;
            result("unreachable-" + c[0], pass, outcome + " after " + millis + " ms");
        }
    }

    /** Both directions busy at once on one connection, then a half-close. */
    static void duplex() throws Exception {
        final int size = 10_000_000;
        final byte[] data = pattern(size, 3);
        final Socket s = connect(host, echoPort);
        s.setSoTimeout(60_000);
        final String[] writeError = new String[1];
        Thread writer = new Thread(new Runnable() {
            public void run() {
                try {
                    OutputStream out = s.getOutputStream();
                    out.write(data);
                    out.flush();
                    s.shutdownOutput();
                } catch (Throwable t) {
                    writeError[0] = t.toString();
                }
            }
        });
        long start = System.currentTimeMillis();
        writer.start();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        long received = 0;
        String readError = null;
        try {
            InputStream in = s.getInputStream();
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                md.update(buf, 0, n);
                received += n;
            }
        } catch (Throwable t) {
            readError = t.toString();
        }
        writer.join(60_000);
        s.close();
        long millis = System.currentTimeMillis() - start;
        boolean ok = received == size && hex(md.digest()).equals(sha256(data)) && writeError[0] == null && readError == null;
        result("duplex-10MB-echo", ok, "echoed " + received + "/" + size + " bytes in " + millis + " ms, " + mbps(received, millis)
                + (writeError[0] != null ? ", write: " + writeError[0] : "") + (readError != null ? ", read: " + readError : ""));
    }

    // ---- UDP --------------------------------------------------------------------------------

    static void udp() throws Exception {
        InetAddress address = InetAddress.getByName(host);
        // single datagrams of growing size; above ~1472 bytes they have to be fragmented
        for (int size : new int[]{1, 512, 1200, 1400, 1472, 4000, 8000}) {
            DatagramSocket socket = new DatagramSocket();
            socket.setSoTimeout(3000);
            byte[] data = pattern(size, size);
            String outcome;
            try {
                socket.send(new DatagramPacket(data, size, address, udpPort));
                DatagramPacket reply = new DatagramPacket(new byte[65536], 65536);
                socket.receive(reply);
                outcome = Arrays.equals(data, Arrays.copyOf(reply.getData(), reply.getLength())) ? "ok" : "CORRUPTED (" + reply.getLength() + " bytes back)";
            } catch (Throwable t) {
                outcome = t.getClass().getSimpleName() + ": " + t.getMessage();
            }
            socket.close();
            result("udp-echo-" + size, outcome.equals("ok"), outcome);
        }

        // a burst on one socket: how many come back, and are they intact?
        // paced, because the emulator's own NAT drops datagrams of a faster burst even without a VPN
        int burst = 500;
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(1500);
        socket.setReceiveBufferSize(4 * 1024 * 1024);
        final Set<Integer> seen = new HashSet<>();
        int corrupted = 0;
        for (int i = 0; i < burst; i++) {
            byte[] data = pattern(600, i);
            data[0] = (byte) (i >> 8);
            data[1] = (byte) i;
            socket.send(new DatagramPacket(data, data.length, address, udpPort));
            if (i % 5 == 4) Thread.sleep(4);
        }
        try {
            while (seen.size() < burst) {
                DatagramPacket reply = new DatagramPacket(new byte[2048], 2048);
                socket.receive(reply);
                int index = ((reply.getData()[0] & 0xFF) << 8) | (reply.getData()[1] & 0xFF);
                byte[] expected = pattern(600, index);
                expected[0] = (byte) (index >> 8);
                expected[1] = (byte) index;
                if (reply.getLength() == 600 && Arrays.equals(expected, Arrays.copyOf(reply.getData(), 600))) seen.add(index);
                else corrupted++;
            }
        } catch (SocketTimeoutException e) {
            // no more replies
        }
        socket.close();
        result("udp-burst-" + burst, seen.size() >= burst * 0.80 && corrupted == 0,
                seen.size() + "/" + burst + " echoed intact, " + corrupted + " corrupted");

        // many sockets, one datagram each
        int sockets = 100;
        int answered = 0;
        for (int i = 0; i < sockets; i++) {
            DatagramSocket one = new DatagramSocket();
            one.setSoTimeout(2000);
            try {
                byte[] data = pattern(100, i);
                one.send(new DatagramPacket(data, data.length, address, udpPort));
                DatagramPacket reply = new DatagramPacket(new byte[2048], 2048);
                one.receive(reply);
                if (reply.getLength() == 100) answered++;
            } catch (Throwable t) {
                // counted below
            }
            one.close();
        }
        result("udp-sockets-" + sockets, answered == sockets, answered + "/" + sockets + " separate sockets got their echo");
    }

    // ---- TLS (public servers, any certificate accepted) -------------------------------------

    static SSLSocketFactory trustAllFactory;

    static void initTls() throws Exception {
        if (trustAllFactory != null) return;
        TrustManager[] trustAll = {new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] chain, String authType) { }
            public void checkServerTrusted(X509Certificate[] chain, String authType) { }
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
        }};
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, trustAll, new SecureRandom());
        trustAllFactory = context.getSocketFactory();
        HttpsURLConnection.setDefaultSSLSocketFactory(trustAllFactory);
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) { return true; }
        });
    }

    /** Outcome of one HTTPS exchange. */
    static class TlsFetch {
        int status = -1;
        long bytes;
        long declared = -1;
        String issuer = "?";
        String error;
        long millis;

        boolean complete() {
            return error == null && status >= 200 && status < 400 && (declared < 0 || declared == bytes);
        }

        String describe() {
            return (error != null ? "error after " + bytes + " bytes: " + error : "status " + status + ", " + bytes + " bytes"
                    + (declared >= 0 && declared != bytes ? " of " + declared + " DECLARED" : "")) + ", " + millis + " ms, issuer " + issuer;
        }
    }

    static TlsFetch httpsGet(String url, boolean closeConnection, byte[] postBody) {
        TlsFetch f = new TlsFetch();
        long start = System.currentTimeMillis();
        HttpsURLConnection c = null;
        try {
            initTls();
            c = (HttpsURLConnection) new URL(url).openConnection();
            c.setConnectTimeout(CONNECT_TIMEOUT);
            c.setReadTimeout(READ_TIMEOUT);
            c.setRequestProperty("User-Agent", "heimdall-stress");
            c.setRequestProperty("Accept-Encoding", "identity");
            if (closeConnection) c.setRequestProperty("Connection", "close");
            if (postBody != null) {
                c.setDoOutput(true);
                c.setRequestMethod("POST");
                c.setFixedLengthStreamingMode(postBody.length);
                OutputStream out = c.getOutputStream();
                out.write(postBody);
                out.close();
            }
            f.status = c.getResponseCode();
            X509Certificate leaf = (X509Certificate) c.getServerCertificates()[0];
            String dn = leaf.getIssuerX500Principal().getName();
            f.issuer = dn.replaceAll(".*CN=([^,]+).*", "$1");
            f.declared = c.getContentLengthLong();
            InputStream in = f.status < 400 ? c.getInputStream() : c.getErrorStream();
            byte[] buf = new byte[65536];
            int n;
            while (in != null && (n = in.read(buf)) > 0) f.bytes += n;
        } catch (Throwable t) {
            f.error = t.toString();
        } finally {
            if (c != null) c.disconnect();
        }
        f.millis = System.currentTimeMillis() - start;
        return f;
    }

    static final String[] TLS_SITES = {
            "https://www.wikipedia.org/", "https://www.cloudflare.com/", "https://www.mozilla.org/en-US/",
            "https://github.com/", "https://www.bbc.com/", "https://www.amazon.com/", "https://www.microsoft.com/",
            "https://stackoverflow.com/", "https://www.reddit.com/", "https://www.apple.com/",
            "https://www.debian.org/", "https://www.kernel.org/", "https://www.python.org/", "https://www.rust-lang.org/",
            "https://httpbin.org/get", "https://postman-echo.com/get", "https://example.com/", "https://www.heise.de/"
    };

    /** One request to each of a set of public sites. */
    static void tls() {
        for (String site : TLS_SITES) {
            TlsFetch f = httpsGet(site, false, null);
            result("tls-" + site.replaceAll("https://([^/]+)/.*", "$1"), f.error == null && f.status > 0, f.describe());
        }
        // a TLS 1.2-only client
        try {
            initTls();
            SSLSocket s = (SSLSocket) trustAllFactory.createSocket();
            s.connect(new InetSocketAddress("www.wikipedia.org", 443), CONNECT_TIMEOUT);
            s.setSoTimeout(READ_TIMEOUT);
            s.setEnabledProtocols(new String[]{"TLSv1.2"});
            s.startHandshake();
            // keep-alive on purpose: a server that closes right after responding is tlsclose's subject
            s.getOutputStream().write("GET / HTTP/1.1\r\nHost: www.wikipedia.org\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            String head = readHead(s.getInputStream());
            result("tls-1.2-only-client", head.startsWith("HTTP/1.1 "), s.getSession().getProtocol() + ", " + head.split("\r\n")[0]);
            s.close();
        } catch (Throwable t) {
            result("tls-1.2-only-client", false, t.toString());
        }
    }

    /** Large transfers through TLS. */
    static void tlsBulk() {
        for (int size : new int[]{1_000_000, 25_000_000}) {
            TlsFetch f = httpsGet("https://speed.cloudflare.com/__down?bytes=" + size, false, null);
            result("tlsbulk-download-" + size, f.complete() && f.bytes == size, f.describe() + ", " + mbps(f.bytes, f.millis));
        }
        for (int size : new int[]{100_000, 5_000_000}) {
            TlsFetch f = httpsGet("https://speed.cloudflare.com/__up", false, pattern(size, 1));
            result("tlsbulk-upload-" + size, f.error == null && f.status == 200, f.describe() + ", " + mbps(size, f.millis));
        }
        byte[] body = "{\"probe\":\"heimdall-stress\"}".getBytes(StandardCharsets.UTF_8);
        TlsFetch echo = httpsGet("https://postman-echo.com/post", false, body);
        result("tlsbulk-post-echo", echo.error == null && echo.status == 200, echo.describe());
    }

    /** Requests after which the server closes the connection at once. */
    static void tlsClose() {
        int total = 40;
        int complete = 0;
        List<String> problems = new ArrayList<>();
        for (int i = 0; i < total; i++) {
            String site = i % 2 == 0 ? "https://speed.cloudflare.com/__down?bytes=" + (3000 + i * 997)
                    : "https://www.wikipedia.org/static/favicon/wikipedia.ico?i=" + i;
            TlsFetch f = httpsGet(site, true, null);
            if (f.complete() && f.bytes > 0) complete++;
            else if (problems.size() < 4) problems.add(f.describe());
        }
        result("tlsclose-" + total, complete == total, complete + "/" + total + " responses complete with Connection: close " + problems);
    }

    /** Many TLS connections at once. */
    static void tlsParallel() throws Exception {
        final int rounds = 4;
        List<Callable<Boolean>> tasks = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        for (int r = 0; r < rounds; r++) {
            for (final String site : TLS_SITES) {
                tasks.add(new Callable<Boolean>() {
                    public Boolean call() {
                        TlsFetch f = httpsGet(site, false, null);
                        boolean ok = f.error == null && f.status > 0;
                        if (!ok) synchronized (errors) { if (errors.size() < 4) errors.add(site + ": " + f.describe()); }
                        return ok;
                    }
                });
            }
        }
        long start = System.currentTimeMillis();
        int ok = runAll(tasks, 24, 240, errors);
        result("tlsparallel-" + tasks.size(), ok == tasks.size(), ok + "/" + tasks.size() + " ok in " + (System.currentTimeMillis() - start) + " ms " + errors);
    }
}

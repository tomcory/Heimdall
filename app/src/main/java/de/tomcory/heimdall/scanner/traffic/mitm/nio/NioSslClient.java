package de.tomcory.heimdall.scanner.traffic.mitm.nio;

/**
 * An SSL/TLS client that connects to a server using its IP address and port.
 * <p/>
 * <p/>
 * When the connection between the client and the object is established, {@link NioSslClient} provides
 * a public write and read method, in order to communicate with its peer.
 *
 * @author <a href="mailto:alex.a.karnezis@gmail.com">Alex Karnezis</a>
 */
public class NioSslClient/* extends NioSslPeer*/ {
//
//    /**
//     * The remote address of the server this client is configured to connect to.
//     */
//    private final InetSocketAddress remoteAddress;
//
//    /**
//     * The socket channel that will be used as the transport link between this client and the server.
//     */
//    private SocketChannel socketChannel;
//
//
//    /**
//     * Initiates the engine to run as a client using peer information, and allocates space for the
//     * buffers that will be used by the engine.
//     *
//     * @param remoteAddress The IP address of the peer.
//     * @param engine The SSLEngine that will be used.
//     */
//    public NioSslClient(InetSocketAddress remoteAddress, SSLEngine engine, SocketChannel socketChannel) throws Exception  {
//        super(engine);
//        this.remoteAddress = remoteAddress;
//    }
//
//    /**
//     * Opens a socket channel to communicate with the configured server and tries to complete the handshake protocol.
//     *
//     * @return True if client established a connection with the server, false otherwise.
//     */
//    public boolean connect() throws Exception {
//        socketChannel = SocketChannel.open();
//        socketChannel.configureBlocking(false);
//        socketChannel.connect(remoteAddress);
//
//        //TODO: replace with selector callback
//        while (!socketChannel.finishConnect()) {
//            // can do something here...
//        }
//
//        engine.beginHandshake();
//        return doHandshakeNonBlocking(socketChannel);
//    }
//
//    /**
//     * Public method to send a message to the server.
//     *
//     * @param message - message to be sent to the server.
//     * @throws IOException if an I/O error occurs to the socket channel.
//     */
//    public void write(String message) throws IOException {
//        write(socketChannel, engine, message);
//    }
//
//    /**
//     * Implements the write method that sends a message to the server the client is connected to,
//     * but should not be called by the user, since socket channel and engine are inner class' variables.
//     * {@link NioSslClient#write(String)} should be called instead.
//     *
//     * @param message - message to be sent to the server.
//     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
//     * @throws IOException if an I/O error occurs to the socket channel.
//     */
//    @Override
//    protected void write(SocketChannel socketChannel, SSLEngine engine, String message) throws IOException {
//
//        Timber.d("About to write to the server...");
//
//        myAppData.clear();
//        myAppData.put(message.getBytes());
//        myAppData.flip();
//        while (myAppData.hasRemaining()) {
//            // The loop has a meaning for (outgoing) messages larger than 16KB.
//            // Every wrap call will remove 16KB from the original message and send it to the remote peer.
//            myNetData.clear();
//            SSLEngineResult result = engine.wrap(myAppData, myNetData);
//            switch (result.getStatus()) {
//                case OK:
//                    myNetData.flip();
//                    while (myNetData.hasRemaining()) {
//                        socketChannel.write(myNetData);
//                    }
//                    Timber.d("Message sent to the server: %s", message);
//                    break;
//                case BUFFER_OVERFLOW:
//                    myNetData = enlargePacketBuffer(engine, myNetData);
//                    break;
//                case BUFFER_UNDERFLOW:
//                    throw new SSLException("Buffer underflow occured after a wrap. I don't think we should ever get here.");
//                case CLOSED:
//                    closeConnection(socketChannel);
//                    return;
//                default:
//                    throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
//            }
//        }
//
//    }
//
//    /**
//     * Public method to try to read from the server.
//     */
//    public void read() throws Exception {
//        read(socketChannel, engine);
//    }
//
//    /**
//     * Will wait for response from the remote peer, until it actually gets something.
//     * Uses {@link SocketChannel#read(ByteBuffer)}, which is non-blocking, and if
//     * it gets nothing from the peer, waits for {@code waitToReadMillis} and tries again.
//     * <p/>
//     * Just like {@link NioSslClient#read(SocketChannel, SSLEngine)} it uses inner class' socket channel
//     * and engine and should not be used by the client. {@link NioSslClient#read()} should be called instead.
//     *
//     * @param socketChannel - channel used for communication with the server
//     * @param engine - the engine used for encryption/decryption of the data exchanged between the two peers.
//     */
//    @Override
//    protected void read(SocketChannel socketChannel, SSLEngine engine) throws Exception  {
//
//        Timber.d("About to read from the server...");
//
//        peerNetData.clear();
//        int waitToReadMillis = 50;
//        boolean exitReadLoop = false;
//        while (!exitReadLoop) {
//            int bytesRead = socketChannel.read(peerNetData);
//            if (bytesRead > 0) {
//                peerNetData.flip();
//                while (peerNetData.hasRemaining()) {
//                    peerAppData.clear();
//                    SSLEngineResult result = engine.unwrap(peerNetData, peerAppData);
//                    switch (result.getStatus()) {
//                        case OK:
//                            peerAppData.flip();
//                            Timber.d("Server response: %s", new String(peerAppData.array()));
//                            exitReadLoop = true;
//                            break;
//                        case BUFFER_OVERFLOW:
//                            peerAppData = enlargeApplicationBuffer(engine, peerAppData);
//                            break;
//                        case BUFFER_UNDERFLOW:
//                            peerNetData = handleBufferUnderflow(engine, peerNetData);
//                            break;
//                        case CLOSED:
//                            closeConnection(socketChannel);
//                            return;
//                        default:
//                            throw new IllegalStateException("Invalid SSL status: " + result.getStatus());
//                    }
//                }
//            } else if (bytesRead < 0) {
//                handleEndOfStream(socketChannel);
//                return;
//            }
//            Thread.sleep(waitToReadMillis);
//        }
//    }
//
//    /**
//     * Should be called when the client wants to explicitly close the connection to the server.
//     *
//     * @throws IOException if an I/O error occurs to the socket channel.
//     */
//    public void shutdown() throws IOException {
//        Timber.d("About to close connection with the server...");
//        closeConnection(socketChannel);
//        executor.shutdown();
//        Timber.d("Goodbye!");
//    }
}

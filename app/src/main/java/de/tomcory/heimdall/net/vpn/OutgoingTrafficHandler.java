package de.tomcory.heimdall.net.vpn;

import static de.tomcory.heimdall.util.Constants.PROTO_TCP;

import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.os.Process;

import androidx.annotation.NonNull;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.IpNumber;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;

import de.tomcory.heimdall.net.flow.AbstractIp4Flow;
import de.tomcory.heimdall.net.flow.Tcp4Flow;
import de.tomcory.heimdall.net.flow.Udp4Flow;
import de.tomcory.heimdall.net.flow.cache.FlowCache;
import de.tomcory.heimdall.net.metadata.MetadataCollector;
import de.tomcory.heimdall.util.StringUtils;
import timber.log.Timber;

public class OutgoingTrafficHandler extends HandlerThread {

    private Handler handler;
    private final Handler deviceWriteHandler;
    private final Selector socketSelector;
    private final HeimdallVpnService vpnService;

    private final boolean logFlows = true;

    public OutgoingTrafficHandler(@NonNull String name, @NonNull Handler deviceWriteHandler, @NonNull Selector socketSelector, @NonNull HeimdallVpnService vpnService) {
        super(name, Process.THREAD_PRIORITY_FOREGROUND);
        this.deviceWriteHandler = deviceWriteHandler;
        this.socketSelector = socketSelector;
        this.vpnService = vpnService;

        Timber.d("Thread created");
    }

    Handler getHandler() {
        return handler;
    }

    @Override
    protected void onLooperPrepared() {

        handler = new Handler(getLooper()) {
            @Override
            public void handleMessage(@NonNull Message msg) {
                if(msg.obj instanceof IpV4Packet) {
                    IpV4Packet outgoingPacket = (IpV4Packet) msg.obj;

                    if(outgoingPacket.getHeader().getProtocol() == IpNumber.TCP) {
                        handleTcpPacket(outgoingPacket);
                    } else if(outgoingPacket.getHeader().getProtocol() == IpNumber.UDP) {
                        handleUdpPacket(outgoingPacket);
                    } else {
                        Timber.e("Packet has unsupported transport protocol: %s", outgoingPacket.getHeader().getProtocol().toString());
                    }

                } else if(msg.obj instanceof IpV6Packet) {
                    //TODO: add IPv6 support
                    Timber.e("IPv6 is not supported yet!");

                } else {
                    Timber.e("Got unknown message type: " + msg.obj.getClass().getName() + " (should be org.pcap4j.packet.IpV4Packet)");
                }
            }
        };

        // send signal that this thread is prepared
        Timber.d("Looper prepared");
        synchronized (HeimdallVpnService.threadReadyMonitor) {
            HeimdallVpnService.threadReadyMonitor.notifyAll();
        }
    }

    private void handleTcpPacket(@NonNull IpV4Packet outgoingPacket) {
        TcpPacket.TcpHeader tcpHeader = (TcpPacket.TcpHeader) outgoingPacket.getPayload().getHeader();

        if(tcpHeader.getAck()) {
            Tcp4Flow flow = (Tcp4Flow) FlowCache.findFlow(outgoingPacket);
            if(flow != null) {

                // update the stats of the corresponding flow
                flow.increaseStats(true, outgoingPacket.length(),
                        outgoingPacket.getPayload().getPayload() == null ? 0 : outgoingPacket.getPayload().getPayload().length());

                if(outgoingPacket.getPayload().getPayload() != null && outgoingPacket.getPayload().getPayload().length() > 0) {
                    // data was sent and needs to be forwarded
                    handleAckData(outgoingPacket, flow);
                } else if(!tcpHeader.getSyn() && !tcpHeader.getFin()) {
                    handleAckEmpty(outgoingPacket, flow);
                }

                if(tcpHeader.getSyn()) {
                    // this should not happen, since we never initiate a handshake
                    handleSynAck(outgoingPacket, flow);
                } else if(tcpHeader.getFin()) {
                    // this is either the first or second packet of the closing handshake
                    handleFinAck(outgoingPacket, flow);
                }
            } else {
                // no flow for packet, abort
                abortAndRst(outgoingPacket);
            }

        } else if(tcpHeader.getFin()) {
            // closing handshake was initiated
            Tcp4Flow flow = (Tcp4Flow) FlowCache.findFlow(outgoingPacket);
            if(flow != null) {
                // update the stats of the corresponding flow
                flow.increaseStats(true, outgoingPacket.length(),
                        outgoingPacket.getPayload().getPayload() == null ? 0 : outgoingPacket.getPayload().getPayload().length());
                handleFin(outgoingPacket, flow);
            } else {
                // no flow for packet, abort
                abortAndRst(outgoingPacket);
            }

        } else if(tcpHeader.getSyn()) {
            // opening handshake was initiated
            handleSyn(outgoingPacket);
        }
    }

    private void handleAckData(@NonNull IpV4Packet outgoingPacket, @NonNull Tcp4Flow flow) {
        TcpPacket tcpPacket = (TcpPacket) outgoingPacket.getPayload();

        if(flow.getFlowStatus() != AbstractIp4Flow.FlowStatus.CONNECTED) {
            // the flow is not ready to forward data, abort
            Timber.e(flow.getFlowId() + ": Got ACK (data, invalid state " + flow.getFlowStatus().name() + ") " + StringUtils.addressOut(outgoingPacket));
            abortAndRst(flow);

        } else {
            // forward TCP payload
            flow.increaseTheirSeqNum(tcpPacket.getPayload().getRawData().length);

            // SocketChannels only accept ByteBuffers as input, so we need to wrap the payload in one
            SocketChannel socketChannel = (SocketChannel) flow.getSelectionKey().channel();
            ByteBuffer buffer = flow.getOutBuffer();
            buffer.clear();
            buffer.put(tcpPacket.getPayload().getRawData());
            buffer.flip();

            while(buffer.hasRemaining()) {
                try {
                    socketChannel.write(buffer);
                } catch (IOException e) {
                    Timber.e(e, flow.getFlowId() + ": Error writing to SocketChannel %s", StringUtils.addressOut(outgoingPacket));
                    abortAndRst(flow);
                    break;
                }
            }

            // acknowledge packet to the client
            IpV4Packet ackResponse = flow.buildEmptyAck();
            // update the stats of the corresponding flow
            flow.increaseStats(false, ackResponse.length(),
                    ackResponse.getPayload().getPayload() == null ? 0 : ackResponse.getPayload().getPayload().length());
            deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, ackResponse));
        }
    }

    private void handleAckEmpty(@NonNull IpV4Packet outgoingPacket, @NonNull Tcp4Flow flow) {
        //TODO: Android 10 seems to randomly send empty ACKs - why? -> ignoring random ACKs for now
        if(flow.getFlowStatus() == AbstractIp4Flow.FlowStatus.CONNECTING) {
            // establishing handshake complete, set status to CONNECTED
            flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CONNECTED);

        } else if(flow.getFlowStatus() == AbstractIp4Flow.FlowStatus.CLOSING) {
            // closing handshake complete, set status to CLOSED
            flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CLOSED);
            FlowCache.removeFlow(flow);
        }
    }

    private void handleSynAck(@NonNull IpV4Packet outgoingPacket, @NonNull Tcp4Flow flow) {
        // SYN ACK packets should not be sent by the client, abort
        Timber.w(flow.getFlowId() + ": Got SYN ACK (invalid) %s", StringUtils.addressOut(outgoingPacket));
        abortAndRst(flow);
    }

    private void handleFinAck(@NonNull IpV4Packet outgoingPacket, @NonNull Tcp4Flow flow) {
        if(flow.getFlowStatus() == AbstractIp4Flow.FlowStatus.CLOSING) {
            // flow is closing, so this must be an actual FIN ACK - acknowledge it and close the flow for good
            flow.increaseTheirSeqNum(1);
            IpV4Packet ackResponse = flow.buildEmptyAck();
            // update the stats of the corresponding flow
            flow.increaseStats(false, ackResponse.length(),
                    ackResponse.getPayload().getPayload() == null ? 0 : ackResponse.getPayload().getPayload().length());
            deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, ackResponse));

        } else {
            // we're not expecting a FIN ACK, so we treat it like a normal FIN packet and start closing the flow
            handleFin(outgoingPacket, flow);
        }
    }

    private void handleFin(@NonNull IpV4Packet outgoingPacket, @NonNull Tcp4Flow flow) {
        if(flow.getFlowStatus() == AbstractIp4Flow.FlowStatus.CLOSED) {
            // the flow is already closed, abort
            abortAndRst(flow);

        } else {
            try {
                // close asynchronously
                synchronized (HeimdallVpnService.selectorMonitor) {
                    flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CLOSING);
                    socketSelector.wakeup();
                    flow.getSelectionKey().channel().close();
                }
            } catch (IOException e) {
                Timber.e(e, flow.getFlowId() + ": Error closing SocketChannel %s", StringUtils.addressOut(outgoingPacket));
            }
            flow.increaseTheirSeqNum(1);
            IpV4Packet finAckResponse = flow.buildFinAck();
            flow.increaseOurSeqNum(1);
            // update the stats of the corresponding flow
            flow.increaseStats(false, finAckResponse.length(),
                    finAckResponse.getPayload().getPayload() == null ? 0 : finAckResponse.getPayload().getPayload().length());
            deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, finAckResponse));
        }
    }

    private void handleSyn(@NonNull IpV4Packet outgoingPacket) {
        // initiate establishing handshake
        if(FlowCache.findFlow(outgoingPacket) == null) {
            Timber.d("Got SYN (handshake) %s", StringUtils.addressOut(outgoingPacket));

            // create a matching object for the new flow
            Tcp4Flow flow;
            try {
                flow = (Tcp4Flow) AbstractIp4Flow.getInstance(outgoingPacket, logFlows, vpnService.getSessionId());

                // spawn a MetadataCollector thread that asynchronously queries external APIs for metadata such as the flow's target geolocation
                new MetadataCollector(flow, vpnService.getApplicationContext()).start();

                // update the stats of the corresponding flow
                flow.increaseStats(true, outgoingPacket.length(),
                        outgoingPacket.getPayload().getPayload() == null ? 0 : outgoingPacket.getPayload().getPayload().length());

                // SYN packets increase the sender's sequence number by 1
                flow.increaseTheirSeqNum(1);

                flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CONNECTING);

                // create a non-blocking SocketChannel to which to forward data and protect it from the VPN
                SocketChannel socketChannel;
                try {
                    // open the channel now, but connect it asynchronously for better performance
                    socketChannel = SocketChannel.open();
                    vpnService.protect(socketChannel.socket());
                    socketChannel.configureBlocking(false);
                    socketChannel.socket().setKeepAlive(true);
                    socketChannel.socket().setTcpNoDelay(true);
                    socketChannel.socket().setSoTimeout(0);
                    socketChannel.socket().setReceiveBufferSize(65535);
                    TcpPacket.TcpHeader tcpHeader = (TcpPacket.TcpHeader) outgoingPacket.getPayload().getHeader();
                    socketChannel.connect(new InetSocketAddress(outgoingPacket.getHeader().getDstAddr().getHostAddress(), tcpHeader.getDstPort().valueAsInt()));

                } catch (IOException e) {
                    Timber.e(e, flow.getFlowId() + ": Error opening SocketChannel %s", StringUtils.addressOut(outgoingPacket));
                    abortAndRst(flow);
                    return;
                }

                // register OP_CONNECT interest for the channel
                try {
                    synchronized (HeimdallVpnService.selectorMonitor) {
                        socketSelector.wakeup();
                        SelectionKey selectionKey = socketChannel.register(socketSelector, SelectionKey.OP_CONNECT);
                        flow.setSelectionKey(selectionKey);
                        selectionKey.attach(flow);
                    }

                } catch (ClosedChannelException e) {
                    Timber.e(e, flow.getFlowId() + ": Error registering SocketChannel %s", StringUtils.addressOut(outgoingPacket));
                    abortAndRst(flow);
                }

            } catch (AbstractIp4Flow.UnsupportedProtocolException e) {
                Timber.e(e, "Error creating new TcpConnection %s", StringUtils.addressOut(outgoingPacket));
                abortAndRst(outgoingPacket);
            }

        } else {
            // ignore duplicate SYN
            Timber.w("Got SYN (duplicate) %s", StringUtils.addressOut(outgoingPacket));
        }
    }

    private void abortAndRst(@NonNull Tcp4Flow flow) {
        IpV4Packet rstResponse = flow.buildRst();
        flow.setFlowStatus(AbstractIp4Flow.FlowStatus.ABORTED);
        FlowCache.removeFlow(flow);
        // update the stats of the corresponding flow
        flow.increaseStats(false, rstResponse.length(),
                rstResponse.getPayload().getPayload() == null ? 0 : rstResponse.getPayload().getPayload().length());
        deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, rstResponse));
    }

    private void abortAndRst(@NonNull IpV4Packet strayPacket) {
        Timber.w("Resetting unknown flow");
        IpV4Packet rstResponse = Tcp4Flow.buildRstForUnknownConnection(strayPacket);
        deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, rstResponse));
    }

    private void handleUdpPacket(@NonNull IpV4Packet outgoingPacket) {

        // retrieve the corresponding UdpConnection, if one exists
        Udp4Flow flow = null;
        try {
            flow = (Udp4Flow) FlowCache.findFlow(outgoingPacket);
        } catch (Exception e) {
            System.out.println(FlowCache.findFlow(outgoingPacket).toString());
            System.out.println(outgoingPacket.toString());
            e.printStackTrace();
            System.exit(2);
        }

        if(flow == null) {

            // create a matching object for the new flow
            try {
                // create a UdpConnection object
                Udp4Flow newFlow = (Udp4Flow) AbstractIp4Flow.getInstance(outgoingPacket, logFlows, vpnService.getSessionId());

                if (!newFlow.isDns()) {

                    // spawn a MetadataCollector thread that asynchronously queries external APIs for metadata such as the flow's target geolocation
                    new MetadataCollector(newFlow, vpnService.getApplicationContext()).start();
                }

                // forward the outgoing packet
                writeUdpPacketToSocket(outgoingPacket, newFlow);

            } catch (AbstractIp4Flow.UnsupportedProtocolException e) {
                Timber.e(e, "Error creating new UdpConnection %s", StringUtils.addressOut(outgoingPacket));
            }
        } else {
            // forward the outgoing packet
            writeUdpPacketToSocket(outgoingPacket, flow);
        }
    }

    private void writeUdpPacketToSocket(IpV4Packet outgoingPacket, Udp4Flow flow) {
        UdpPacket udpPacket = (UdpPacket) outgoingPacket.getPayload();
        UdpPacket.UdpHeader udpHeader = udpPacket.getHeader();

        if(!flow.isDns()) {
            // update the stats of the corresponding flow
            flow.increaseStats(true, outgoingPacket.length(),
                    outgoingPacket.getPayload().getPayload() == null ? 0 : outgoingPacket.getPayload().getPayload().length());
        }

        DatagramChannel datagramChannel;
        if(flow.getFlowStatus() != AbstractIp4Flow.FlowStatus.CONNECTED && flow.getFlowStatus() != AbstractIp4Flow.FlowStatus.CONNECTING) {
            // create a non-blocking DatagramChannel to which to forward data and protect it from the VPN
            try {
                // open the channel now, but connect it asynchronously for better performance
                flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CONNECTING);
                datagramChannel = DatagramChannel.open();
                vpnService.protect(datagramChannel.socket());
                datagramChannel.configureBlocking(false);
                datagramChannel.socket().setSoTimeout(0);
                datagramChannel.socket().setReceiveBufferSize(65535);
                datagramChannel.connect(new InetSocketAddress(outgoingPacket.getHeader().getDstAddr().getHostAddress(), udpHeader.getDstPort().valueAsInt()));

            } catch (IOException e) {
                Timber.e(e, flow.getFlowId() + ": Error opening DatagramChannel %s", StringUtils.addressOut(outgoingPacket));
                FlowCache.removeFlow(flow);
                return;
            }

            // register OP_READ interest for the channel
            try {
                synchronized (HeimdallVpnService.selectorMonitor) {
                    socketSelector.wakeup();
                    SelectionKey selectionKey = datagramChannel.register(socketSelector, SelectionKey.OP_READ);
                    flow.setSelectionKey(selectionKey);
                    selectionKey.attach(flow);
                }

            } catch (ClosedChannelException e) {
                Timber.e(e, flow.getFlowId() + ": Error registering DatagramChannel %s", StringUtils.addressOut(outgoingPacket));
                FlowCache.removeFlow(flow);
                return;
            }
        } else {
            datagramChannel = (DatagramChannel) flow.getSelectionKey().channel();
        }

        if(udpPacket.getPayload() != null) {
            ByteBuffer buffer = flow.getOutBuffer();
            buffer.clear();
            buffer.put(udpPacket.getPayload().getRawData());
            buffer.flip();

            while(buffer.hasRemaining()) {
                try {
                    datagramChannel.write(buffer);
                } catch (IOException | BufferOverflowException e) {
                    Timber.e(e, flow.getFlowId() + ": Error writing to DatagramChannel %s", StringUtils.addressOut(outgoingPacket));
                    FlowCache.removeFlow(flow);
                    break;
                }
            }
        }
    }

    @Override
    public boolean quit() {
        Timber.d("Thread shut down");
        return super.quit();
    }

    @Override
    public boolean quitSafely() {
        Timber.d("Thread shut down");
        return super.quit();
    }
}

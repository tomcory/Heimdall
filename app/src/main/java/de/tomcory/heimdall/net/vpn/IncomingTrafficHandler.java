package de.tomcory.heimdall.net.vpn;

import static de.tomcory.heimdall.util.Constants.PROTO_TCP;
import static de.tomcory.heimdall.util.Constants.PROTO_UDP;

import android.os.Handler;
import android.os.Process;

import androidx.annotation.NonNull;

import org.pcap4j.packet.DnsPacket;
import org.pcap4j.packet.DnsRDataA;
import org.pcap4j.packet.DnsRDataAaaa;
import org.pcap4j.packet.DnsResourceRecord;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Objects;

import de.tomcory.heimdall.net.flow.AbstractIp4Flow;
import de.tomcory.heimdall.net.flow.Tcp4Flow;
import de.tomcory.heimdall.net.flow.Udp4Flow;
import de.tomcory.heimdall.net.flow.cache.DnsCache;
import de.tomcory.heimdall.net.flow.cache.FlowCache;
import de.tomcory.heimdall.util.StringUtils;
import timber.log.Timber;

public class IncomingTrafficHandler extends Thread {

    private final Handler deviceWriteHandler;
    private final Selector socketSelector;

    public IncomingTrafficHandler(@NonNull String name, @NonNull Handler deviceWriteHandler, @NonNull Selector socketSelector) {
        super(name);
        this.deviceWriteHandler = deviceWriteHandler;
        this.socketSelector = socketSelector;
        Process.setThreadPriority(Process.THREAD_PRIORITY_FOREGROUND);

        Timber.d("Thread created");
    }

    @Override
    public void run() {
        Timber.d("Thread started");

        int selectedChannels;
        //ByteBuffer buffer = ByteBuffer.allocate(65495); //65495

        while(!interrupted()) {

            selectedChannels = 0;
            try {
                selectedChannels = socketSelector.select();
            } catch (IOException e) {
                Timber.e(e, "Error during selection process");
            }

            synchronized (HeimdallVpnService.selectorMonitor) {
                if(selectedChannels > 0) {
                    Iterator<SelectionKey> iterator = socketSelector.selectedKeys().iterator();
                    while(iterator.hasNext()) {
                        SelectionKey key = iterator.next();

                        if (key.attachment() == null) {
                            Timber.e("Channel has null attachment");
                            key.cancel();
                            continue;
                        }

                        if (key.attachment() instanceof Tcp4Flow) {
                            handleTcp(key);
                        } else if (key.attachment() instanceof Udp4Flow) {
                            handleUdp(key);
                        } else {
                            Timber.e("Unsupported channel attachment type: %s", key.attachment().getClass().getSimpleName());
                        }
                        iterator.remove();
                    }
                }
            }
        }

        Timber.d("Thread shut down");
    }

    private void handleTcp(@NonNull SelectionKey key) {
        Tcp4Flow flow = (Tcp4Flow) key.attachment();
        SocketChannel socketChannel = (SocketChannel) key.channel();

        if(!key.isValid()) {
            Timber.d("Invalid Selection key %s", StringUtils.address(flow));
            abort(key, flow);
            return;
        }

        if (key.isConnectable()) {
            // OP_CONNECT event triggered

            // complete the SocketChannel's connection process
            try {
                socketChannel.finishConnect();
            } catch (IOException e) {
                Timber.e(e, "Error connecting SocketChannel %s", StringUtils.address(flow));
                abort(key, flow);
                return;
            }

            // make sure the SocketChannel is actually connected
            if (socketChannel.isConnected()) {

                // prepare SocketChannel for incoming data and complete local handshake
                key.interestOps(SelectionKey.OP_READ);
                IpV4Packet synAckPacket = flow.buildSynAck();
                flow.increaseOurSeqNum(1);
                // update the stats of the corresponding flow
                flow.increaseStats(false, synAckPacket.length(),
                        synAckPacket.getPayload().getPayload() == null ? 0 : synAckPacket.getPayload().getPayload().length());
                deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, synAckPacket));

            } else {
                Timber.e("Error connecting SocketChannel %s", StringUtils.address(flow));
                abort(key, flow);
            }

        } else if (key.isReadable()) {
            // OP_READ event triggered

            int bytesRead;
            ByteBuffer buffer = flow.getInBuffer();
            do {
                try {
                    // read and forward the incoming data chunk by chunk (i.e. loop as long as data is read)
                    buffer.clear();
                    bytesRead = socketChannel.read(buffer);
                    if (bytesRead > 0) {
                        buffer.flip();

                        byte[] rawData = Arrays.copyOf(buffer.array(), bytesRead);
                        IpV4Packet ackDataPacket = flow.buildDataAck(rawData);
                        flow.increaseOurSeqNum(bytesRead);
                        // update the stats of the corresponding flow
                        flow.increaseStats(false, ackDataPacket.length(),
                                ackDataPacket.getPayload().getPayload() == null ? 0 : ackDataPacket.getPayload().getPayload().length());
                        deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, ackDataPacket));
                    }

                } catch (IOException e) {
                    Timber.e(e, "Error reading data from SocketChannel %s", StringUtils.address(flow));
                    bytesRead = -1;
                }
            } while (bytesRead > 0);

            // SocketChannel is closed, initiate local FIN handshake
            if (bytesRead == -1) {
                key.cancel();

                if (flow.getFlowStatus() != AbstractIp4Flow.FlowStatus.CLOSING) {
                    // connection closed by server, move to CLOSING state
                    flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CLOSING);
                }

                IpV4Packet finAckPacket = flow.buildFinAck();
                flow.increaseOurSeqNum(1);
                // update the stats of the corresponding flow
                flow.increaseStats(false, finAckPacket.length(),
                        finAckPacket.getPayload().getPayload() == null ? 0 : finAckPacket.getPayload().getPayload().length());
                deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, finAckPacket));
            }
        }
    }

    private void handleUdp(@NonNull SelectionKey key) {
        Udp4Flow flow = (Udp4Flow) key.attachment();
        DatagramChannel datagramChannel = (DatagramChannel) key.channel();

        if (key.isReadable()) {
            int bytesRead;
            ByteBuffer buffer = flow.getInBuffer();
            do {
                try {
                    // read and forward the incoming data chunk by chunk
                    buffer.clear();
                    bytesRead = datagramChannel.read(buffer);
                    if (bytesRead > 0) {
                        buffer.flip();
                        byte[] rawData = Arrays.copyOf(buffer.array(), bytesRead);

                        IpV4Packet forwardPacket = flow.buildPacket(rawData);

                        if(flow.isDns()) {
                            byte[] rawDns = forwardPacket.getPayload().getPayload().getRawData();
                            try {
                                DnsPacket.DnsHeader dnsHeader = DnsPacket.newPacket(rawDns, 0, rawDns.length).getHeader();
                                if(dnsHeader.getrCode().value() == 0) {
                                    String hostname = dnsHeader.getQuestions().get(0).getQName().toString();
                                    for(DnsResourceRecord data : dnsHeader.getAnswers()) {
                                        if(data.getRData() instanceof DnsRDataA) {
                                            String address = ((DnsRDataA) data.getRData()).getAddress().getHostAddress();
                                            DnsCache.addHost(Objects.requireNonNull(address), hostname);
                                        } else if(data.getRData() instanceof DnsRDataAaaa) {
                                            String address = ((DnsRDataAaaa) data.getRData()).getAddress().getHostAddress();
                                            DnsCache.addHost(Objects.requireNonNull(address), hostname);
                                        }
                                    }
                                }
                            } catch (IllegalRawDataException e) {
                                Timber.e(e, "Error parsing DNS response");
                            }
                        } else {
                            // update the stats of the corresponding flow (only non-DNS)
                            flow.increaseStats(false, forwardPacket.length(),
                                    forwardPacket.getPayload().getPayload() == null ? 0 : forwardPacket.getPayload().getPayload().length());
                        }


                        deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_UDP, forwardPacket));
                    }

                } catch (IOException e) {
                    Timber.e(e, "Error reading data from DatagramChannel %s", StringUtils.address(flow));
                    bytesRead = -1;
                }
            } while (bytesRead > 0);

            // no need to keep DNS connections open after the first and only packet
            if(flow.getRemotePort().valueAsInt() == 53) {
                try {
                    datagramChannel.close();
                } catch (IOException e) {
                    Timber.e(e, "Error closing DatagramChannel %s", StringUtils.address(flow));
                }
                bytesRead = -1;
            }

            // DatagramChannel is closed
            if (bytesRead == -1) {
                flow.setFlowStatus(AbstractIp4Flow.FlowStatus.CLOSED);
                FlowCache.removeFlow(flow);
                key.cancel();
            }
        }
    }

    private void abort(SelectionKey key, Tcp4Flow flow) {
        key.cancel();
        IpV4Packet rstPacket = flow.buildRst();
        flow.setFlowStatus(AbstractIp4Flow.FlowStatus.ABORTED);
        FlowCache.removeFlow(flow);
        // update the stats of the corresponding flow (only non-DNS)
        flow.increaseStats(false, rstPacket.length(),
                rstPacket.getPayload().getPayload() == null ? 0 : rstPacket.getPayload().getPayload().length());
        deviceWriteHandler.sendMessage(deviceWriteHandler.obtainMessage(PROTO_TCP, rstPacket));
    }
}

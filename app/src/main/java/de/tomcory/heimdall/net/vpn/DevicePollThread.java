package de.tomcory.heimdall.net.vpn;

import android.os.Handler;
import android.os.Process;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructPollfd;
import android.util.Log;

import androidx.annotation.NonNull;

import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;

import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

import de.tomcory.heimdall.util.BytesToHex;
import timber.log.Timber;

public class DevicePollThread extends Thread {

    private final Handler outgoingHandler;

    private final FileInputStream inputStream;
    private final FileDescriptor interrupter;

    DevicePollThread(@NonNull String name, @NonNull FileInputStream inputStream, @NonNull FileDescriptor interrupter, @NonNull Handler outgoingHandler) {
        super(name);
        this.inputStream = inputStream;
        this.interrupter = interrupter;
        this.outgoingHandler = outgoingHandler;
        Process.setThreadPriority(Process.THREAD_PRIORITY_FOREGROUND);
        Timber.d("Thread created ");
    }

    @Override
    public void run() {
        Timber.d("Thread started");

        // allocate the buffer for a single packet and reuse it for all packets (yay, performance!)
        byte[] packet = new byte[1500];

        // prepare to poll the inputStream
        StructPollfd deviceFd = new StructPollfd();
        try {
            deviceFd.fd = inputStream.getFD();
        } catch (IOException e) {
            Timber.e(e, "Error getting FileDescriptor of VPN interface");
            return;
        }
        deviceFd.events = (short) OsConstants.POLLIN;

        // prepare to poll the interrupter pipe
        StructPollfd interruptFd = new StructPollfd();
        interruptFd.fd = this.interrupter;
        interruptFd.events = (short) (OsConstants.POLLHUP | OsConstants.POLLERR);

        // combine the FileDescriptors into an array for Os.poll()
        StructPollfd[] polls = new StructPollfd[2];
        polls[0] = deviceFd;
        polls[1] = interruptFd;

        Timber.d("Thread configured, polling VPN interface");

        // continuously poll until interrupted via the interrupter pipe (in which case poll() returns false)
        while(true) {
            if(!poll(packet, polls)) {
                break;
            }
        }
        Timber.d("Thread shut down");
    }

    private boolean poll(@NonNull byte[] packetPlaceholder, @NonNull StructPollfd[] polls) {

        StructPollfd deviceFd = polls[0];
        StructPollfd interruptFd = polls[1];

        // use Os.poll to poll all FileDescriptors
        int result = 0;
        try {
            result = Os.poll(polls, -1);
        } catch (ErrnoException e) {
            Timber.e(e, "Error during Os.poll()");
        }

        // unlikely to happen due to unlimited timeout on Os.poll, but still, handle timeout
        if(result == 0) {
            Timber.e("Os.poll() timed out");
            return true;
        }

        // an event was written to the interrupter FileDescriptor, telling us to interrupt
        if(interruptFd.revents != 0) {
            Timber.d("Told to stop VPN");
            return false;
        }

        // the POLLIN event was written to the deviceFd Filedescriptor, meaning we need to read a packet from the device
        if((deviceFd.revents & OsConstants.POLLIN) != 0) {
            byte[] packet = readPacket(inputStream, packetPlaceholder);

            // make sure the packet is an IPv4 packet
            //TODO: support IPv6
            if(packet[0] >> 4 == 6) {
                Timber.d("Ignoring Ipv6 Packet");
                return true;
            }

            // make sure we got the whole packet
            int statedLength = ((packet[2] << 8) & 0xFFFF) + (packet[3] & 0xFF);
            if(statedLength != packet.length) {
                Timber.d("Packet length mismatch: Stated length: " + statedLength + " - Actual length: " + packet.length + " - Difference: " + (packet.length - statedLength));
            }

            // parse the packet to a pcap4j packet
            IpV4Packet parsedPacket;
            try {
                parsedPacket = IpV4Packet.newPacket(packet, 0, packet.length);
            } catch (IllegalRawDataException e) {
                Timber.d("Read packet: %s", BytesToHex.bytesToHex(packet));
                Timber.e(e, "Illegal raw packet");
                return true;
            }

            // some apps keep sending packets to the general broadcast address, ignore these packets
            if(Objects.equals(parsedPacket.getHeader().getDstAddr().getHostAddress(), "255.255.255.255")) {
                //Log.w(TAG, "Ignoring 255.255.255.255 broadcast packet");
                return true;
            }

            // forward the packet to the OutgoingTrafficHandler
            outgoingHandler.sendMessage(outgoingHandler.obtainMessage(parsedPacket.getHeader().getProtocol().value(), parsedPacket));
        }
        return true;
    }

    @NonNull
    private byte[] readPacket(@NonNull FileInputStream inputStream, @NonNull byte[] packet) {

        // Read the outgoing packet from the input stream.
        int length = 0;
        try {
            length = inputStream.read(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // no need to process completely empty packets
        if(length == 0) {
            return new byte[0];
        }

        // continue with a copy of the packet, preventing access and garbage collection problems
        return Arrays.copyOfRange(packet, 0, length);
    }
}
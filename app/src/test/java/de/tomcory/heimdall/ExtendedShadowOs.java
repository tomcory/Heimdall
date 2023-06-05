package de.tomcory.heimdall;

import android.os.ParcelFileDescriptor;
import android.system.Os;

import org.robolectric.annotation.Implementation;
import org.robolectric.annotation.Implements;
import org.robolectric.shadows.ShadowOsConstants;

import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.IOException;

@Implements(Os.class)
public class ExtendedShadowOs {

    private static ParcelFileDescriptor[] interruptPair;

    @Implementation
    protected static FileDescriptor[] pipe() {
        System.out.println("PIPE CALLED");
        try {
            interruptPair = ParcelFileDescriptor.createPipe();
            FileDescriptor in = interruptPair[0].getFileDescriptor();
            FileDescriptor out = interruptPair[1].getFileDescriptor();
            return new FileDescriptor[]{in, out};
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    @Implementation
    protected static void close(FileDescriptor fd) {
        System.out.println("CLOSE CALLED");
        try {
            interruptPair[0].close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Implementation
    protected static int poll(android.system.StructPollfd[] fds, int timeoutMs) {
        System.out.println("POLL CALLED");
        close(null);
        return 0;
    }
}

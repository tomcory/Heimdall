package de.tomcory.heimdall;

import static org.junit.Assert.*;

import android.content.Intent;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.android.controller.ServiceController;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowLog;

import de.tomcory.heimdall.vpn.components.HeimdallVpnService;
import de.tomcory.heimdall.persistence.database.HeimdallDatabase;

@RunWith(RobolectricTestRunner.class)
public class HttpTest {

    private ServiceController<HeimdallVpnService> controller;
    private HeimdallVpnService service;

    @Before
    public void setUpService() {

        ShadowLog.stream = System.out;

        HeimdallDatabase.init(RuntimeEnvironment.getApplication());

        Intent serviceIntent = new Intent(RuntimeEnvironment.getApplication(), HeimdallVpnService.class);
        serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.START_SERVICE);

        controller = Robolectric.buildService(HeimdallVpnService.class, serviceIntent);
        controller.startCommand(HeimdallVpnService.START_SERVICE, 0);
        service = controller.get();
        System.out.println("Service has SessionId " + service.getSessionId());
    }

    @After
    public void tearDownService() {
        controller.destroy();
    }

    @Test
    @Config(shadows={ExtendedShadowOs.class})
    public void testServiceStart() {
        try {
            Thread.sleep(2000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        assertTrue(service.isVpnActive());
    }
}

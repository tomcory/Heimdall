package de.tomcory.heimdall.ui.apps

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import de.tomcory.heimdall.R
import de.tomcory.heimdall.databinding.FragmentAppsBinding
import de.tomcory.heimdall.net.vpn.HeimdallVpnService
import timber.log.Timber
import java.net.NetworkInterface
import java.net.SocketException
import java.util.*

class AppsFragment : Fragment() {

    private var vpnActive = false

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        val binding: FragmentAppsBinding = DataBindingUtil.inflate(
                inflater, R.layout.fragment_apps, container, false)


        Timber.d("Loading AppsFragment")

        binding.lifecycleOwner = viewLifecycleOwner

        binding.appsPager.adapter = AppsPagerAdapter(this)

        binding.appsTabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab?) {
                val colorString = when(tab!!.position) {
                    0 -> requireContext().resources.getStringArray(R.array.paletteRed50)[0]
                    1 -> requireContext().resources.getStringArray(R.array.paletteAmber50)[0]
                    2 -> requireContext().resources.getStringArray(R.array.paletteGreen50)[0]
                    else -> requireContext().resources.getStringArray(R.array.paletteLightBlue50)[0]
                }

                binding.appsTabLayout.setSelectedTabIndicatorColor(Color.parseColor(colorString))
            }

            override fun onTabUnselected(tab: TabLayout.Tab?) {
            }

            override fun onTabReselected(tab: TabLayout.Tab?) {

            }
        })

        binding.fabVpn.setOnClickListener {
            vpnActive = !vpnActive
            if (vpnActive) {

                Thread {

                    //start the VPN
                    startVpn()
                    binding.fabVpn.setImageResource(R.drawable.launch_button_active)
                }.start()

            } else {
                stopVpn()
                binding.fabVpn.setImageResource(R.drawable.launch_button_inactive)
            }
        }

        TabLayoutMediator(binding.appsTabLayout, binding.appsPager) { tab, position ->
            when (position) {
                0 -> {
                    tab.text = "Flows"
                    binding.appsTabLayout.setSelectedTabIndicatorColor(
                            Color.parseColor(requireContext().resources.getStringArray(R.array.paletteRed50)[0])
                    )
                }
                1 -> {
                    tab.text = "Traffic"
                    binding.appsTabLayout.setSelectedTabIndicatorColor(
                            Color.parseColor(requireContext().resources.getStringArray(R.array.paletteRed50)[0])
                    )
                }
                2 -> {
                    tab.text = "Upload"
                    binding.appsTabLayout.setSelectedTabIndicatorColor(
                            Color.parseColor(requireContext().resources.getStringArray(R.array.paletteRed50)[0])
                    )
                }
                3 -> {
                    tab.text = "Download"
                    binding.appsTabLayout.setSelectedTabIndicatorColor(
                            Color.parseColor(requireContext().resources.getStringArray(R.array.paletteRed50)[0])
                    )
                }
            }
        }.attach()

        Timber.d("AppsFragment loaded")

        return binding.root
    }

    private fun startVpn() {

        // make sure we are connected to the Internet
        if (!checkInternetConnected()) {
            Toast.makeText(context, "No Internet connection", Toast.LENGTH_SHORT).show()
            return
        }

        // make sure the network interface isn't already in use
        if (!checkNoActiveInterface()) {
            Toast.makeText(context, "Network interface already in use", Toast.LENGTH_SHORT).show()
            return
        }

        // launch VPN permission request dialog if this is the first time the VPN is started
        val intent = VpnService.prepare(context)
        if (intent != null) {
            // launch dialog
            startActivityForResult(intent, 0)
        } else {
            // skip straight past the dialog, pretend it was OK
            onActivityResult(0, Activity.RESULT_OK, null)
        }
    }

    private fun stopVpn() {
        if (activity != null) {
            val serviceIntent = Intent(context, HeimdallVpnService::class.java)
            serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.STOP_SERVICE)
            requireActivity().startService(serviceIntent)
        }
    }

    private fun checkInternetConnected(): Boolean {
        //TODO: implement
        return true
    }

    private fun checkNoActiveInterface(): Boolean {
        try {
            for (networkInterface in Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (networkInterface.name == "tun0" && networkInterface.isUp) {
                    return false
                }
            }
        } catch (e: SocketException) {
            e.printStackTrace()
        }
        return true
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)

        if (requestCode == 0 && resultCode == Activity.RESULT_OK && activity != null) {
            val serviceIntent = Intent(context, HeimdallVpnService::class.java)
            serviceIntent.putExtra(HeimdallVpnService.VPN_ACTION, HeimdallVpnService.START_SERVICE)
            requireActivity().startForegroundService(serviceIntent)

        }
    }
}
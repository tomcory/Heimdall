package de.tomcory.heimdall.ui.apps

import android.os.Bundle
import androidx.fragment.app.Fragment
import androidx.viewpager2.adapter.FragmentStateAdapter
import de.tomcory.heimdall.ui.apps.page.ARG_POS
import de.tomcory.heimdall.ui.apps.page.AppsPageFragment
import timber.log.Timber

class AppsPagerAdapter(
        fragment: Fragment
) : FragmentStateAdapter(fragment) {

    override fun getItemCount(): Int {
        return 4
    }

    override fun createFragment(position: Int): Fragment {
        val fragment = AppsPageFragment()
        fragment.arguments = Bundle().apply {
            putInt(ARG_POS, position)
        }
        return fragment
    }
}
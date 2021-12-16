package de.tomcory.heimdall.ui.apps.page

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.databinding.DataBindingUtil
import androidx.fragment.app.Fragment
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import de.tomcory.heimdall.R
import de.tomcory.heimdall.databinding.FragmentAppsPageBinding
import de.tomcory.heimdall.persistence.database.TrafficDatabase
import kotlinx.coroutines.ExperimentalCoroutinesApi
import timber.log.Timber

class AppsPageFragment : Fragment() {

    private lateinit var viewModel: AppsPageViewModel
    private lateinit var binding: FragmentAppsPageBinding
    private lateinit var adapter : AppsPageListAdapter

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {

        binding = DataBindingUtil.inflate(
                inflater, R.layout.fragment_apps_page, container, false)


        Timber.d("Loading AppsPageFragment")

        val position = arguments?.getInt(ARG_POS) ?: 0

        val viewModelFactory = AppsPageViewModelFactory(
                requireActivity().application,
                position,
                TrafficDatabase.getInstance()
        )
        viewModel = ViewModelProvider(this, viewModelFactory).get(AppsPageViewModel::class.java)

        adapter = AppsPageListAdapter(viewModel)

        binding.viewModel = viewModel
        binding.lifecycleOwner = this
        binding.appsPageContainer.adapter = adapter
        binding.appsPageContainer.layoutManager = LinearLayoutManager(activity)

        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {

        viewModel.data.observe(viewLifecycleOwner, {
            it?.let {
                adapter.submitList(viewModel.data.value)
            }
        })
    }
}
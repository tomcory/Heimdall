package de.tomcory.heimdall.ui.apps.page

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import com.github.mikephil.charting.animation.Easing
import com.github.mikephil.charting.data.PieData
import com.github.mikephil.charting.data.PieDataSet
import com.github.mikephil.charting.data.PieEntry
import de.tomcory.heimdall.databinding.ListHeaderAppBinding
import de.tomcory.heimdall.databinding.ListItemAppBinding
import de.tomcory.heimdall.persistence.database.entity.App
import de.tomcory.heimdall.ui.bindings.DataBoundViewHolder
import timber.log.Timber

const val ITEM_VIEW_TYPE_HEADER = 0
const val ITEM_VIEW_TYPE_ITEM = 1

class AppsPageListAdapter(private val viewModel: AppsPageViewModel) :
        ListAdapter<App.AppGrouped, DataBoundViewHolder>(AppsDiffCallback()) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): DataBoundViewHolder {
        val viewHolder = when (viewType) {
            ITEM_VIEW_TYPE_HEADER -> HeaderViewHolder.from(parent)
            ITEM_VIEW_TYPE_ITEM -> ItemViewHolder.from(parent)
            else -> throw ClassCastException("Unknown viewType $viewType")
        }

        viewHolder.binding.lifecycleOwner = viewHolder
        viewHolder.markCreated()
        return viewHolder
    }

    override fun onBindViewHolder(holder: DataBoundViewHolder, position: Int) {
        when (holder) {
            is HeaderViewHolder -> {
                holder.bind(
                        currentList.subList(1, currentList.size).map { app -> PieEntry(app.value.toFloat()) },
                        viewModel)
            }
            is ItemViewHolder -> {
                holder.bind(
                        getItem(position)!!,
                        viewModel.colors[(position - 1) % 4],
                        viewModel)
            }
        }
    }

    override fun getItemViewType(position: Int): Int {
        return getItem(position).type
    }

    override fun onViewAttachedToWindow(holder: DataBoundViewHolder) {
        super.onViewAttachedToWindow(holder)
        holder.markAttach()
    }

    override fun onViewDetachedFromWindow(holder: DataBoundViewHolder) {
        super.onViewDetachedFromWindow(holder)
        holder.markDetach()
    }

    class HeaderViewHolder private constructor(override val binding: ListHeaderAppBinding) : DataBoundViewHolder(binding) {

        fun bind(currentList: List<PieEntry>, viewModel: AppsPageViewModel) {
            binding.viewModel = viewModel
            binding.executePendingBindings()

            val pieDataSet = PieDataSet(currentList, "")
            pieDataSet.colors = viewModel.colors
            pieDataSet.sliceSpace = 3f
            pieDataSet.selectionShift = 5f
            pieDataSet.setDrawValues(false)
            pieDataSet.setDrawIcons(false)

            val pieData = PieData(pieDataSet)
            val pieChart = binding.pieChartApps
            pieChart.data = pieData
            pieChart.setDrawEntryLabels(false)
            pieChart.legend.isEnabled = false
            pieChart.description.isEnabled = false
            pieChart.holeRadius = 97f
            pieChart.transparentCircleRadius = 97f
            pieChart.setTouchEnabled(false)

            if(viewModel.firstLoad) {
                pieChart.animateY(1000, Easing.EaseInOutExpo)
            }

            pieChart.highlightValues(null)
            pieChart.invalidate()
        }

        companion object {
            fun from(parent: ViewGroup): HeaderViewHolder {
                val binding = ListHeaderAppBinding.inflate(
                        LayoutInflater.from(parent.context),
                        parent,
                        false
                )
                return HeaderViewHolder(binding)
            }
        }
    }

    class ItemViewHolder private constructor(override val binding: ListItemAppBinding) : DataBoundViewHolder(binding) {

        fun bind(app: App.AppGrouped, color: Int, viewModel: AppsPageViewModel) {

            binding.app = app
            binding.progressColor = color
            binding.viewModel = viewModel

            binding.executePendingBindings()
        }

        companion object {
            fun from(parent: ViewGroup): ItemViewHolder {
                val binding = ListItemAppBinding.inflate(
                        LayoutInflater.from(parent.context),
                        parent,
                        false
                )
                return ItemViewHolder(binding)
            }
        }
    }
}

class AppsDiffCallback : DiffUtil.ItemCallback<App.AppGrouped>() {

    override fun areItemsTheSame(oldItem: App.AppGrouped, newItem: App.AppGrouped): Boolean {
        return oldItem.appPackage == newItem.appPackage
    }

    override fun areContentsTheSame(oldItem: App.AppGrouped, newItem: App.AppGrouped): Boolean {
        return oldItem == newItem
    }
}
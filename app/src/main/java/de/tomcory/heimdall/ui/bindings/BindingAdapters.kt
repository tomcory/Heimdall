package de.tomcory.heimdall.ui.bindings

import android.widget.ProgressBar
import android.widget.TextView
import androidx.databinding.BindingAdapter
import de.tomcory.heimdall.persistence.database.entity.App
import java.text.DecimalFormat
import java.text.DecimalFormatSymbols

@BindingAdapter("value", "unit")
fun TextView.setValueFormatted(value: Long, unit: String) {

    val valueFormatted = when {
        value < 1_000 -> {
            val formatted = DecimalFormat("#.##", DecimalFormatSymbols.getInstance()).format(value)
            if(unit.isEmpty()) {
                formatted
            } else {
                "$formatted $unit"
            }
        }
        value < 1_000_000 -> {
            val shortValue = value.div(1_000.toDouble())
            val formatted = DecimalFormat("#.##", DecimalFormatSymbols.getInstance()).format(shortValue)
            "$formatted K${unit}"
        }
        value < 1_000_000_000 -> {
            val shortValue = value.div(1_000_000.toDouble())
            val formatted = DecimalFormat("#.##", DecimalFormatSymbols.getInstance()).format(shortValue)
            "$formatted M${unit}"
        }
        else -> {
            val shortValue = value.div(1_000_000_000.toDouble())
            val formatted = DecimalFormat("#.##", DecimalFormatSymbols.getInstance()).format(shortValue)
            "$formatted G${unit}"
        }
    }

    text = valueFormatted

}

@BindingAdapter("percentageRounded")
fun ProgressBar.setPercentageRounded(item: App.AppGrouped?) {
    item?.let {
        progress = (item.percentage * 100).toInt()
    }
}
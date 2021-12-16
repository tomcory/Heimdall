package de.tomcory.heimdall.ui.activity;

import android.os.Bundle;

import androidx.appcompat.app.AppCompatActivity;

import de.tomcory.heimdall.R;
import timber.log.Timber;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Timber.d("MainActivity created");
    }
}

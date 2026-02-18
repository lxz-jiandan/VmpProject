package com.example.vmengine;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import com.example.vmengine.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'vmengine' library on application startup.
    static {
        System.loadLibrary("vmengine");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

    }

}
package com.example.vmengine;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import com.example.vmengine.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // 应用启动时加载 native 库。
    // JNI_OnLoad 会在这里被触发，完成 VM 引擎初始化与样例函数执行。
    static {
        System.loadLibrary("vmengine");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        // 当前 Activity 仅承担最小壳层职责：
        // 1) 初始化 ViewBinding
        // 2) 提供基础 UI 容器
        // VM 逻辑全部在 native 层完成。
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

    }

}

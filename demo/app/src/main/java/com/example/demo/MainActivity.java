// [VMP_FLOW_NOTE] 文件级流程注释
// - Demo 应用入口，触发 bridge JNI 并展示 fun_* 的调用结果。
// - 加固链路位置：设备端 UI 展示层。
// - 输入：bridge 返回的多行函数执行结果。
// - 输出：界面展示 + logcat 结果。
package com.example.demo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.example.demo.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "VMP_DEMO";

    // 只加载桥接库 bridge。
    // bridge 通过链接期依赖自动拉起 libdemo.so，不再使用运行时 dlsym。
    static {
        System.loadLibrary("bridge");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        TextView tv = binding.sampleText;
        String resultText = getProtectResults();
        Log.i(TAG, "onCreate protect results:\n" + resultText);
        tv.setText(resultText);
    }

    public native String getProtectResults();
}

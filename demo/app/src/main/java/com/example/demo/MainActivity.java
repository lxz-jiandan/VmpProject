// [VMP_FLOW_NOTE] 文件级流程注释
// - Demo 应用入口，触发受保护 so 的 JNI 冒烟验证。
// - 加固链路位置：端到端验证 UI 层。
// - 输入：native 返回的 PASS/FAIL 文本。
// - 输出：界面展示 + logcat 关键字。
package com.example.demo;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import com.example.demo.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {
    private static final String TAG = "VMP_DEMO";

    // 这里只加载桥接库 demo_jni。
    // 被保护的 libdemo.so 在 native 桥接层通过 dlopen 主动加载，
    // 避免 demo app 依赖 vmengine 的 JNI_OnLoad 时序。
    static {
        System.loadLibrary("demo_jni");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        TextView tv = binding.sampleText;
        // onCreate 即触发一次完整的 native 对照测试，结果直接落到 UI 文本。
        String checkResult = runVmpSmokeCheck();
        Log.i(TAG, "onCreate smoke check: " + checkResult);
        tv.setText(checkResult);
    }

    public native String runVmpSmokeCheck();
}

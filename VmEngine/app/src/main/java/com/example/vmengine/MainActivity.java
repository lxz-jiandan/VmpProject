// [VMP_FLOW_NOTE] 文件级流程注释
// - VmEngine 示例应用入口，负责触发 vmengine native 初始化链路。
// - 加固链路位置：引擎演示壳层 UI。
// - 输入：Android 生命周期事件。
// - 输出：JNI_OnLoad 执行与基础页面容器。
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
        // VM 逻辑（payload 解析/dispatch/takeover）全部在 native 层完成。
        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

    }

}

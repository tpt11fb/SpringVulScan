package burp;

import java.io.PrintWriter;

import burp.UI.Tags;
import burp.Scan.Scanner;

public class BurpExtender implements IBurpExtender
{
    private final String name = "SpringVulScan";
    private final String version = "1.0";

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Tags tags;
    private Scanner scanner;//Scanner 实现了IScannerCheck接口


    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        // 设置拓展名称
        this.callbacks.setExtensionName(name);
        //该方法用于获得一个 IExtensionHelpers目的， 扩展程序可以使用它来执行许多有用的任务。
        this.helpers = this.callbacks.getHelpers();
        // 获取输入输出流
        this.stderr = new PrintWriter(this.callbacks.getStderr(), true);
        this.stdout = new PrintWriter(this.callbacks.getStdout(), true);
        // 添加tag标签到ui
        this.tags = new Tags(callbacks, this.name);

        // 初始化 scanner
        this.scanner = new Scanner(this);

        // 注册 Scanner
        this.callbacks.registerScannerCheck(this.scanner);

        //打印插件信息
        this.stdout.println(this.extenderInfo());
    }


    public String extenderInfo(){
        String info = "===========================\n" +
                "[+]   load successful!     \n" +
                "[+]   SpringVulScan V1.0       \n" +
                "[+]   code by Tptfb11     \n" +
                "[+]   GitHUub: https://github.com/tpt11fb   \n";
        String payload = "目前支持：\n" +
                "[+] Spring Core RCE (CVE-2022-22965)\n" +
                "[+] Spring Cloud Function SpEL RCE (CVE-2022-22963)\n" +
                "[+] Spring Cloud GateWay SPEL RCE (CVE-2022-22947)\n" +
                "[+] Spring Security OAuth2 RCE (CVE-2016-4977)\n" +
                "[+] API 未授权、泄露\n" +
                "===========================\n";
        return info + payload;
    }
}
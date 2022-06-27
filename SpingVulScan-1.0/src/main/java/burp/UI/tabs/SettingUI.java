package burp.UI.tabs;

import burp.IBurpExtenderCallbacks;
import java.awt.Color;
import java.awt.Font;
import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.border.EmptyBorder;

public class SettingUI {
   private IBurpExtenderCallbacks callbacks;
   private JTabbedPane tabs;
   private JTabbedPane reverseTabs;
   private JCheckBox enableCheckBox;
   private JCheckBox errorCheckBox;
   private JCheckBox reverseCheckBox;
   private JCheckBox checkAll;
   private JCheckBox checkSpring;
   private JLabel enableLabel;
   private JLabel checkLabel;
   private JLabel reverseLabel;
   private JLabel scanLabel;
   private JLabel vulId;
   private JPanel backendUI;
   private JTextField othersDnsLog;
   private JComboBox<String> backendSelector;
   private JComboBox<String> vulSelector;

   public SettingUI(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
      this.callbacks = callbacks;
      this.tabs = tabs;
      this.initUI();
      this.tabs.addTab("设置", this.backendUI);
   }

   public SettingUI() {
      this.initUI();
   }

   public JPanel getBackendUI() {
      return this.backendUI;
   }

   public void initUI() {
      this.backendUI = new JPanel();
      this.backendUI.setAlignmentX(0.0F);
      this.backendUI.setBorder(new EmptyBorder(0, 0, 0, 0));
      this.backendUI.setLayout(new BoxLayout(this.backendUI, 1));
      this.enableLabel = new JLabel("基础设置：");
      this.scanLabel = new JLabel("扫描类型：");
      this.checkLabel = new JLabel("检测方式：");
      this.reverseLabel = new JLabel("回连平台：");
      this.vulId = new JLabel("检测编号：");
      this.enableCheckBox = new JCheckBox("启动", true);
      this.errorCheckBox = new JCheckBox("回显检测", true);
      this.reverseCheckBox = new JCheckBox("回连检测", true);
      this.checkAll = new JCheckBox("同一站点仅检测一次", true);
      this.checkSpring = new JCheckBox("过滤检测Spring框架流量", true);
      this.enableLabel.setForeground(new Color(255, 89, 18));
      this.enableLabel.setFont(new Font("Serif", 0, this.enableLabel.getFont().getSize() + 2));
      this.scanLabel.setForeground(new Color(255, 89, 18));
      this.scanLabel.setFont(new Font("Serif", 0, this.scanLabel.getFont().getSize() + 2));
      this.checkLabel.setForeground(new Color(255, 89, 18));
      this.checkLabel.setFont(new Font("Serif", 0, this.checkLabel.getFont().getSize() + 2));
      this.reverseLabel.setForeground(new Color(255, 89, 18));
      this.reverseLabel.setFont(new Font("Serif", 0, this.reverseLabel.getFont().getSize() + 2));
      this.vulId.setForeground(new Color(255, 89, 18));
      this.vulId.setFont(new Font("Serif", 0, this.vulId.getFont().getSize() + 2));
      this.vulSelector = new JComboBox(this.getvulIDSelectors());
      this.vulSelector.setSelectedIndex(0);
      this.vulSelector.setMaximumSize(this.vulSelector.getPreferredSize());
      this.backendSelector = new JComboBox(this.getbackendSelectors());
      this.backendSelector.setSelectedIndex(0);
      this.backendSelector.setMaximumSize(this.backendSelector.getPreferredSize());
      this.reverseTabs = new JTabbedPane();
      this.reverseTabs.addTab("DNSLog Platform", this.getCeyePanel());
      JPanel runPanel = this.GetXPanel();
      runPanel.add(this.enableLabel);
      runPanel.add(this.enableCheckBox);
      JPanel scanPanel = this.GetXPanel();
      scanPanel.add(this.scanLabel);
      scanPanel.add(this.checkAll);
      scanPanel.add(this.checkSpring);
      JPanel checkPanel = this.GetXPanel();
      checkPanel.add(this.checkLabel);
      checkPanel.add(this.errorCheckBox);
      checkPanel.add(this.reverseCheckBox);
      JPanel reversePanel = this.GetXPanel();
      reversePanel.add(this.reverseLabel);
      reversePanel.add(this.backendSelector);
      JPanel vulIdPanel = this.GetXPanel();
      vulIdPanel.add(this.vulId);
      vulIdPanel.add(this.vulSelector);
      JPanel settingPanel = this.GetYPanel();
      settingPanel.add(runPanel);
      settingPanel.add(checkPanel);
      settingPanel.add(scanPanel);
      settingPanel.add(vulIdPanel);
      JPanel reverseInfoPanel = this.GetXPanel();
      reverseInfoPanel.add(reversePanel);
      reverseInfoPanel.add(this.reverseTabs);
      this.backendUI.add(settingPanel);
      this.backendUI.add(reverseInfoPanel);
   }

   private JPanel getCeyePanel() {
      JPanel jPanel = new JPanel();
      jPanel.add(new JLabel("可指定请求dns（不支持检测）："));
      this.othersDnsLog = new JTextField("DnsLog.cn", 30);
      jPanel.add(this.othersDnsLog);
      return jPanel;
   }

   public JPanel GetXPanel() {
      JPanel panel = new JPanel();
      panel.setAlignmentX(0.0F);
      panel.setBorder(new EmptyBorder(5, 0, 5, 0));
      return panel;
   }

   public JPanel GetYPanel() {
      JPanel panel = new JPanel();
      panel.setAlignmentX(0.0F);
      panel.setBorder(new EmptyBorder(5, 0, 5, 0));
      panel.setLayout(new BoxLayout(panel, 1));
      return panel;
   }

   private String[] getbackendSelectors() {
      ArrayList<String> selectors = new ArrayList();
      SettingUI.Backends[] var2 = SettingUI.Backends.values();
      int var3 = var2.length;

      for(int var4 = 0; var4 < var3; ++var4) {
         SettingUI.Backends backend = var2[var4];
         selectors.add(backend.name().trim());
      }

      return (String[])selectors.toArray(new String[selectors.size()]);
   }

   private String[] getvulIDSelectors() {
      ArrayList<String> selectors = new ArrayList();
      selectors.add("ALL");
      selectors.add("爆破路由，API");
      selectors.add("CVE-2016-4977 Spring Security OAuth2 远程命令执行漏洞");
      selectors.add("CVE-2017-4971 Spring Web Flow 远程代码执行漏洞（待完善）");
      selectors.add("CVE-2018-1270 Spring Messaging 远程命令执行漏洞（待完善）");
      selectors.add("CVE-2018-1273 Spring Data Commons 远程命令执行漏洞（待完善）");
      selectors.add("CVE-2022-22947 Spring Cloud Gateway Actuator API SpEL表达式注入命令执行");
      selectors.add("CVE-2022-22963 Spring Cloud Function SpEL表达式命令注入");
      selectors.add("CVE-2022-22965 Spring Cloud Framework 远程代码执行漏洞");
      return (String[])selectors.toArray(new String[selectors.size()]);
   }

   public boolean isEnable() {
      return this.enableCheckBox.isSelected();
   }

   public boolean isCheckSpring() {
      return this.checkSpring.isSelected();
   }

   public boolean isCheckAll() {
      return this.checkAll.isSelected();
   }

   public boolean isErrorCheck() {
      return this.errorCheckBox.isSelected();
   }

   public boolean isReverseCheck() {
      return this.reverseCheckBox.isSelected();
   }

   public String getVulId() {
      return this.vulSelector.getSelectedItem().toString();
   }

   public SettingUI.Backends getBackendPlatform() {
      return SettingUI.Backends.valueOf(this.backendSelector.getSelectedItem().toString());
   }

   public String getOtherDnsLog() {
      return this.othersDnsLog.getText().trim().toLowerCase();
   }

   public static enum Backends {
      BurpCollaborator,
      DnsLogCn,
      Others;
   }
}

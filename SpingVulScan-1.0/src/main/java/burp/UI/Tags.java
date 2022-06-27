package burp.UI;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.UI.tabs.ScanResultsUI;
import burp.UI.tabs.SettingUI;
import java.awt.Component;
import javax.swing.JTabbedPane;

public class Tags implements ITab {
   private final JTabbedPane tabs;
   private String name;
   private IBurpExtenderCallbacks callbacks;
   private SettingUI settingUI;
   private ScanResultsUI scanResultsUI;

   public Tags(IBurpExtenderCallbacks callbacks, String name) {
      this.callbacks = callbacks;
      this.name = name;
      this.tabs = new JTabbedPane();
      this.settingUI = new SettingUI(callbacks, this.tabs);
      this.scanResultsUI = new ScanResultsUI(callbacks, this.tabs);
      this.callbacks.addSuiteTab(this);
      this.callbacks.customizeUiComponent(this.tabs);
   }

   public SettingUI getSettingUi() {
      return this.settingUI;
   }

   public ScanResultsUI getScannerUi() {
      return this.scanResultsUI;
   }

   public String getTabCaption() {
      return this.name;
   }

   public Component getUiComponent() {
      return this.tabs;
   }
}

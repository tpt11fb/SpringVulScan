package burp.DnsLog.Platform;

import burp.IBurpCollaboratorClientContext;
import burp.IBurpCollaboratorInteraction;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.DnsLog.DnsLogInterface;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class BurpCollaborator implements DnsLogInterface {
   private IBurpExtenderCallbacks callbacks;
   private IExtensionHelpers helpers;
   private IBurpCollaboratorClientContext burpCollaboratorClientContext;
   private String dnsLogName;
   private String tempDomain;
   private String dnslogContent = null;

   public BurpCollaborator(IBurpExtenderCallbacks callbacks) {
      this.callbacks = callbacks;
      this.helpers = callbacks.getHelpers();
      this.dnsLogName = "http://burpcollaborator.net/";
      this.burpCollaboratorClientContext = callbacks.createBurpCollaboratorClientContext();
      this.init();
   }

   public void init() {
      this.tempDomain = this.burpCollaboratorClientContext.generatePayload(true);
      if (this.tempDomain == null || this.tempDomain.length() <= 0) {
         throw new RuntimeException(String.format("请检查本机是否可使用burp自带的dnslog客户端,%s", this.dnsLogName));
      }
   }

   public String getTempDomain() {
      return this.tempDomain;
   }

   public String getBodyContent() {
      List<IBurpCollaboratorInteraction> collaboratorInteractions = this.burpCollaboratorClientContext.fetchCollaboratorInteractionsFor(this.getTempDomain());
      if (collaboratorInteractions != null && !collaboratorInteractions.isEmpty()) {
         Iterator<IBurpCollaboratorInteraction> iterator = collaboratorInteractions.iterator();
         Map<String, String> properties = ((IBurpCollaboratorInteraction)iterator.next()).getProperties();
         if (properties.size() == 0) {
            return this.dnslogContent;
         } else {
            String content = null;

            String text;
            for(Iterator var5 = properties.keySet().iterator(); var5.hasNext(); content = content + text + " ") {
               String property = (String)var5.next();
               text = (String)properties.get(property);
               if (property.equals("raw_query")) {
                  text = new String(this.helpers.base64Decode(text));
               }
            }

            this.dnslogContent = this.dnslogContent + content;
            return this.dnslogContent;
         }
      } else {
         return this.dnslogContent;
      }
   }

   public boolean checkResult() {
      return this.getBodyContent() != null;
   }

   public String outExport() {
      return String.format("BurpDnsLog Domain: %s", this.getTempDomain());
   }

   public void export() {
      PrintWriter stdout = new PrintWriter(this.callbacks.getStdout(), true);
      stdout.println("");
      stdout.println("===========BurpDnsLog扩展详情===========");
      stdout.println(String.format("BurpDnsLog临时域名: %s", this.getTempDomain()));
      stdout.println("===================================");
      stdout.println("");
   }
}

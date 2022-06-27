package burp.payload.RCE;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.DnsLog.DnsLogInterface;
import burp.payload.Payload;

public class WebFlowRCE implements Payload {
   private BurpExtender burpExtender;
   private IHttpRequestResponse updataHttp;

   public WebFlowRCE(BurpExtender burpExtender) {
      this.burpExtender = burpExtender;
   }

   public IScanIssue doCheckVul(IHttpRequestResponse iHttpRequestResponse, DnsLogInterface dnsLogPlatform) {
      return null;
   }

   public IHttpRequestResponse export() {
      return this.updataHttp;
   }
}

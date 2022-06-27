package burp.payload;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.DnsLog.DnsLogInterface;
import burp.DnsLog.Platform.BurpCollaborator;
import burp.DnsLog.Platform.DnsLogCn;
import burp.auxiliary.CheckIsSpring;
import burp.payload.RCE.APIunauthorized;
import burp.payload.RCE.CloudFramework;
import burp.payload.RCE.CloudFuncionSpEl;
import burp.payload.RCE.CloudGatewaySpEl;
import burp.payload.RCE.SecurityOAuth2RCE;
import java.io.FileNotFoundException;
import java.util.Objects;

public class ScanPayload {
   private int isVul;
   private IScanIssue vulDetails;
   private BurpExtender burpExtender;
   private IExtensionHelpers helpers;
   private String vulId;
   private CheckIsSpring checkIsSpring;
   private DnsLogInterface dnsLogPlatform;
   private IHttpRequestResponse vulHttp;

   public ScanPayload(BurpExtender burpExtender, IExtensionHelpers helpers, IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException, InterruptedException {
      this.burpExtender = burpExtender;
      this.helpers = helpers;
      this.vulId = this.burpExtender.tags.getSettingUi().getVulId();
      this.checkIsSpring = new CheckIsSpring(this.burpExtender, this.helpers);
      this.isVul = -1;
      this.initDnslog();
      this.init(iHttpRequestResponse);
   }

   private void init(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
      if (this.vulId.contains("ALL")) {
         this.checkApi(iHttpRequestResponse);
         this.check22_22965(iHttpRequestResponse);
         this.check22_22963(iHttpRequestResponse);
         this.check22_22947(iHttpRequestResponse);
         this.check18_1273(iHttpRequestResponse);
         this.check18_1270(iHttpRequestResponse);
         this.check17_4971(iHttpRequestResponse);
         this.check16_4977(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2016-4977")) {
         this.check16_4977(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2017-4971")) {
         this.check17_4971(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2018-1270")) {
         this.check18_1270(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2018-1273")) {
         this.check18_1273(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2022-22947")) {
         this.check22_22947(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2022-22963")) {
         this.check22_22963(iHttpRequestResponse);
      } else if (this.vulId.contains("CVE-2022-22965")) {
         this.check22_22965(iHttpRequestResponse);
      } else {
         this.checkApi(iHttpRequestResponse);
      }

   }

   public void check22_22965(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
      CloudFramework cloudFramework = new CloudFramework(this.burpExtender, this.helpers, this.checkIsSpring);
      IScanIssue scfIssue = cloudFramework.doCheckVul(iHttpRequestResponse, this.dnsLogPlatform);
      if (scfIssue != null) {
         this.vulHttp = cloudFramework.export();
         this.vulDetails = scfIssue;
         if (Objects.equals(scfIssue.getSeverity(), "Medium")) {
            this.isVul = 0;
         } else if (Objects.equals(scfIssue.getSeverity(), "High")) {
            this.isVul = 1;
         }
      }

   }

   public void check22_22963(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
      CloudFuncionSpEl cloudFuncionSpEl = new CloudFuncionSpEl(this.burpExtender, this.helpers, this.checkIsSpring);
      IScanIssue spelIssue = cloudFuncionSpEl.doCheckVul(iHttpRequestResponse, this.dnsLogPlatform);
      if (spelIssue != null) {
         this.vulHttp = cloudFuncionSpEl.export();
         this.vulDetails = spelIssue;
         this.isVul = 1;
      }

   }

   public void check22_22947(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
      CloudGatewaySpEl cloudGatewaySpEl = new CloudGatewaySpEl(this.burpExtender, this.helpers, this.checkIsSpring);
      IScanIssue spelIssue = cloudGatewaySpEl.doCheckVul(iHttpRequestResponse, this.dnsLogPlatform);
      if (spelIssue != null) {
         this.vulHttp = cloudGatewaySpEl.export();
         this.vulDetails = spelIssue;
         this.isVul = 1;
      }

   }

   public void check18_1273(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
   }

   public void check17_4971(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
   }

   public void check16_4977(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
      SecurityOAuth2RCE SecurityOAuth2RCE = new SecurityOAuth2RCE(this.burpExtender, this.helpers, this.checkIsSpring);
      IScanIssue spelIssue = SecurityOAuth2RCE.doCheckVul(iHttpRequestResponse, this.dnsLogPlatform);
      if (spelIssue != null) {
         this.vulDetails = spelIssue;
         this.vulHttp = SecurityOAuth2RCE.export();
         if (Objects.equals(spelIssue.getSeverity(), "Medium")) {
            this.isVul = 0;
         } else if (Objects.equals(spelIssue.getSeverity(), "High")) {
            this.isVul = 1;
         }
      }

   }

   public void check18_1270(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
   }

   public void checkApi(IHttpRequestResponse iHttpRequestResponse) throws FileNotFoundException {
      APIunauthorized apIunauthorized = new APIunauthorized(this.burpExtender, this.helpers, this.checkIsSpring);
      IScanIssue spelIssue = apIunauthorized.doCheckVul(iHttpRequestResponse, this.dnsLogPlatform);
      this.vulHttp = apIunauthorized.export();
      if (spelIssue != null) {
         this.vulDetails = spelIssue;
         this.isVul = 0;
      }

   }

   private void initDnslog() throws InterruptedException {
      String backendSelected = this.burpExtender.tags.getSettingUi().getBackendPlatform().toString();
      byte var3 = -1;
      switch(backendSelected.hashCode()) {
      case -1244747625:
         if (backendSelected.equals("BurpCollaborator")) {
            var3 = 0;
         }
         break;
      case 459123526:
         if (backendSelected.equals("DnsLogCn")) {
            var3 = 1;
         }
      }

      switch(var3) {
      case 0:
         this.dnsLogPlatform = new BurpCollaborator(this.burpExtender.callbacks);
         break;
      case 1:
         this.dnsLogPlatform = new DnsLogCn(this.burpExtender);
      }

   }

   public IHttpRequestResponse getVulHttp() {
      return this.vulHttp;
   }

   public int getIsVul() {
      return this.isVul;
   }

   public IScanIssue getVulDetails() {
      return this.vulDetails;
   }
}
